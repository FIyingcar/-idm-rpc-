import subprocess
import json
import logging
import os
import sys
import threading
import uuid
import shlex
from datetime import datetime
from flask import Flask, request, jsonify

# 修复Windows控制台编码
def setup_console():
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass
    
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

setup_console()

# 加载配置文件
def load_config():
    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # 验证必要配置项
        if not config.get('idm_path'):
            raise ValueError("配置文件中缺少 idm_path 配置项")
        
        # 设置默认值
        if 'jsonrpc_token' not in config:
            config['jsonrpc_token'] = 'token:'
        
        return config
    except FileNotFoundError:
        print("错误: 找不到配置文件 config.json")
        print("请确保 config.json 文件与 server.py 在同一目录")
        input("按回车键退出...")
        return None
    except json.JSONDecodeError:
        print("错误: 配置文件格式不正确")
        print("请检查 config.json 文件是否为有效的JSON格式")
        input("按回车键退出...")
        return None
    except Exception as e:
        print(f"错误: 加载配置文件失败 - {str(e)}")
        input("按回车键退出...")
        return None

# 加载配置
config = load_config()
if config is None:
    sys.exit(1)

# 创建日志目录
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
log_file = os.path.join(log_dir, f'idm_rpc_{datetime.now().strftime("%Y%m%d")}.log')
log_level = getattr(logging, config.get('log_level', 'INFO'))

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 打印启动信息
def print_startup_info():
    print("\n" + "="*60)
    print("IDM RPC 服务器 v1.0")
    print("="*60)
    print(f"服务器地址: http://{config['host']}:{config['rpc_port']}")
    print(f"IDM路径: {config['idm_path']}")
    print(f"默认保存路径: {config['default_save_path']}")
    print(f"调试模式: {config['debug']}")
    print(f"日志级别: {config.get('log_level', 'INFO')}")
    
    # 检查IDM路径
    idm_exists = os.path.exists(config['idm_path'])
    if idm_exists:
        print("IDM检测: 正常")
    else:
        print("IDM检测: 未找到IDM程序")
        print(f"请检查路径: {config['idm_path']}")
    
    print(f"日志文件: {log_file}")
    print("="*60)
    print("服务器已启动，正在监听请求...")
    print("按 Ctrl+C 停止服务器")
    print("="*60 + "\n")

app = Flask(__name__)

class TaskManager:
    def __init__(self):
        self.tasks = {}
        self.lock = threading.Lock()
    
    def add_task(self, url, save_path, file_name=""):
        task_id = str(uuid.uuid4())[:8]
        task = {
            'task_id': task_id,
            'url': url,
            'save_path': save_path,
            'file_name': file_name,
            'status': '等待中',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': None,
            'error_message': None
        }
        
        with self.lock:
            self.tasks[task_id] = task
        
        logger.info(f"创建任务: {task_id} - {url}")
        return task_id
    
    def update_task(self, task_id, status, error_message=None):
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]['status'] = status
                if status in ['已完成', '失败']:
                    self.tasks[task_id]['completed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if error_message:
                    self.tasks[task_id]['error_message'] = error_message
    
    def get_task(self, task_id):
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_all_tasks(self, limit=100):
        with self.lock:
            tasks = list(self.tasks.values())
            tasks.sort(key=lambda x: x['created_at'], reverse=True)
            return tasks[:limit]

task_manager = TaskManager()

def call_idm(download_url, save_path, file_name=""):
    """调用IDM下载文件"""
    logger.info(f"开始调用IDM: URL={download_url}, 路径={save_path}, 文件名={file_name}")
    
    # 安全检查
    if not download_url:
        return False, "下载链接不能为空"
    
    # 验证URL协议
    if not download_url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
        return False, "不支持的协议类型"
    
    # 防止路径遍历攻击
    if '..' in save_path or (file_name and '..' in file_name):
        return False, "路径或文件名包含非法字符"
    
    # 检查保存路径
    if not os.path.isabs(save_path):
        return False, "保存路径必须是绝对路径"
    
    # 创建保存目录
    try:
        os.makedirs(save_path, exist_ok=True)
        logger.debug(f"创建/确认目录: {save_path}")
    except Exception as e:
        logger.error(f"创建目录失败: {str(e)}")
        return False, f"创建目录失败: {str(e)}"
    
    # 检查IDM是否存在
    idm_path = config['idm_path']
    if not os.path.exists(idm_path):
        logger.error(f"未找到IDM程序: {idm_path}")
        return False, "未找到IDM程序"
    
    logger.info(f"IDM程序存在: {idm_path}")
    
    # 构建IDM命令
    cmd = [
        idm_path,
        '/d', download_url,
        '/p', save_path
    ]
    
    # 添加文件名参数（如果有）
    if file_name and file_name.strip():
        cmd.extend(['/f', file_name.strip()])
        logger.debug(f"使用自定义文件名: {file_name}")
    
    # 添加/n和/a参数，确保开始下载并添加到队列
    cmd.extend(['/n'])
    
    # 构建可读的命令行字符串
    cmd_str = ' '.join([f'"{arg}"' if ' ' in str(arg) else str(arg) for arg in cmd])
    logger.info(f"执行IDM命令: {cmd_str}")
    
    try:
        # 执行命令，隐藏命令行窗口
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        
        # 使用shell=False避免shell注入，但需要正确传递参数
        logger.debug(f"执行命令参数: {cmd}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config['idm_timeout'],
            creationflags=creation_flags,
            shell=False  # 明确设置为False
        )
        
        logger.debug(f"IDM命令执行完成")
        logger.debug(f"返回码: {result.returncode}")
        logger.debug(f"标准输出: {result.stdout}")
        logger.debug(f"标准错误: {result.stderr}")
        
        if result.returncode == 0:
            logger.info(f"IDM调用成功: {download_url}")
            return True, "任务已发送至IDM"
        else:
            error_msg = result.stderr or result.stdout or "未知错误"
            logger.error(f"IDM执行失败，返回码: {result.returncode}")
            logger.error(f"错误信息: {error_msg}")
            return False, f"IDM执行失败: {error_msg}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"调用IDM超时")
        return False, "调用IDM超时"
    except FileNotFoundError:
        logger.error(f"找不到IDM程序: {idm_path}")
        return False, f"找不到IDM程序: {idm_path}"
    except Exception as e:
        logger.error(f"未知错误: {str(e)}", exc_info=True)
        return False, f"内部错误: {str(e)}"

def process_jsonrpc_request(data):
    """处理JSON-RPC 2.0格式的请求"""
    try:
        # 验证JSON-RPC格式
        if not isinstance(data, dict):
            return None, {"code": -32600, "message": "Invalid Request"}
        
        if data.get('jsonrpc') != '2.0':
            return None, {"code": -32600, "message": "Invalid Request"}
        
        method = data.get('method')
        if method != 'aria2.addUri':
            return None, {"code": -32601, "message": f"Method not found: {method}"}
        
        params = data.get('params', [])
        if not isinstance(params, list) or len(params) < 2:
            return None, {"code": -32602, "message": "Invalid params"}
        
        # 验证token
        token = params[0] if len(params) > 0 else ""
        if token != config['jsonrpc_token']:
            return None, {"code": -32603, "message": "Invalid token"}
        
        # 提取URL列表
        urls = params[1] if len(params) > 1 else []
        if not urls or not isinstance(urls, list) or len(urls) == 0:
            return None, {"code": -32602, "message": "No URLs provided"}
        
        # 取第一个URL
        download_url = urls[0]
        
        # 提取选项
        options = params[2] if len(params) > 2 else {}
        if not isinstance(options, dict):
            options = {}
        
        # 提取文件名
        file_name = options.get('out', '')
        
        # 默认保存路径
        save_path = config['default_save_path']
        
        logger.info(f"解析JSON-RPC请求成功: URL={download_url[:100]}..., 文件名={file_name}")
        
        return {
            'url': download_url,
            'save_path': save_path,
            'file_name': file_name,
            'jsonrpc_id': data.get('id'),
            'method': method
        }, None
        
    except Exception as e:
        logger.error(f"解析JSON-RPC请求失败: {str(e)}", exc_info=True)
        return None, {"code": -32700, "message": "Parse error"}

def process_rest_request(data):
    """处理REST API格式的请求"""
    if not isinstance(data, dict):
        return None, "请求数据格式不正确"
    
    download_url = data.get('url')
    if not download_url:
        return None, "缺少下载链接参数"
    
    save_path = data.get('path', config['default_save_path'])
    file_name = data.get('filename', '')
    
    return {
        'url': download_url,
        'save_path': save_path,
        'file_name': file_name,
        'jsonrpc_id': None,
        'method': 'REST'
    }, None

def authenticate_request(data):
    """验证API请求"""
    if not config['enable_auth']:
        return True, ""
    
    # 检查是否是JSON-RPC请求
    if isinstance(data, dict) and data.get('jsonrpc') == '2.0':
        # JSON-RPC使用token验证，在process_jsonrpc_request中已处理
        return True, ""
    
    # REST API使用Bearer token验证
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return False, "缺少认证令牌"
    
    expected_token = f"Bearer {config['api_token']}"
    if auth_header != expected_token:
        return False, "认证令牌无效"
    
    return True, ""

@app.route('/', methods=['POST', 'GET'])
@app.route('/api/add_task', methods=['POST'])
def handle_add_task():
    """处理添加任务请求"""
    # 如果是GET请求，返回API信息
    if request.method == 'GET':
        return jsonify({
            'service': 'IDM RPC Server',
            'version': '1.0',
            'protocols': ['JSON-RPC 2.0', 'REST API'],
            'jsonrpc_methods': {
                'aria2.addUri': '添加下载任务'
            }
        })
    
    # 记录请求详情
    client_ip = request.remote_addr
    logger.info(f"收到来自 {client_ip} 的请求")
    
    # 解析请求数据
    request_data = None
    raw_data = None
    try:
        raw_data = request.data.decode('utf-8') if request.data else ''
        logger.debug(f"原始请求数据: {raw_data[:500]}...")
        
        if raw_data:
            request_data = json.loads(raw_data)
            logger.info(f"请求方法: {request_data.get('method', 'REST')}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {str(e)}")
        logger.debug(f"解析失败的原始数据: {raw_data}")
        return jsonify({'success': False, 'error': '解析JSON数据失败'}), 400
    except Exception as e:
        logger.error(f"解析请求失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': '解析请求数据失败'}), 400
    
    if not request_data:
        logger.error("请求数据为空")
        return jsonify({'success': False, 'error': '请求数据为空'}), 400
    
    # 验证请求
    auth_ok, auth_msg = authenticate_request(request_data)
    if not auth_ok:
        logger.warning(f"认证失败: {auth_msg}")
        if isinstance(request_data, dict) and request_data.get('jsonrpc') == '2.0':
            return jsonify({
                'jsonrpc': '2.0',
                'id': request_data.get('id'),
                'error': {'code': -32603, 'message': auth_msg}
            })
        else:
            return jsonify({'success': False, 'error': auth_msg}), 401
    
    # 根据请求类型处理
    is_jsonrpc = isinstance(request_data, dict) and request_data.get('jsonrpc') == '2.0'
    
    if is_jsonrpc:
        # 处理JSON-RPC请求
        task_info, error = process_jsonrpc_request(request_data)
        if error:
            return jsonify({
                'jsonrpc': '2.0',
                'id': request_data.get('id'),
                'error': error
            })
    else:
        # 处理REST API请求
        task_info, error = process_rest_request(request_data)
        if error:
            return jsonify({'success': False, 'error': error}), 400
    
    # 执行下载任务
    download_url = task_info['url']
    save_path = task_info['save_path']
    file_name = task_info['file_name']
    
    logger.info(f"开始处理下载任务: URL={download_url[:100]}...")
    
    # 创建任务记录
    task_id = task_manager.add_task(download_url, save_path, file_name)
    
    # 立即执行下载
    task_manager.update_task(task_id, '处理中')
    success, message = call_idm(download_url, save_path, file_name)
    
    if success:
        task_manager.update_task(task_id, '已完成')
        logger.info(f"任务成功: {task_id}")
        
        if is_jsonrpc:
            return jsonify({
                'jsonrpc': '2.0',
                'id': task_info['jsonrpc_id'],
                'result': task_id
            })
        else:
            return jsonify({
                'success': True,
                'message': message,
                'task_id': task_id
            })
    else:
        task_manager.update_task(task_id, '失败', message)
        logger.error(f"任务失败: {task_id} - {message}")
        
        if is_jsonrpc:
            return jsonify({
                'jsonrpc': '2.0',
                'id': task_info['jsonrpc_id'],
                'error': {
                    'code': -32000,
                    'message': message
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': message,
                'task_id': task_id
            }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    idm_exists = os.path.exists(config['idm_path'])
    
    return jsonify({
        'status': '运行正常',
        'idm_available': idm_exists,
        'total_tasks': len(task_manager.tasks),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'config': {
            'idm_path': config['idm_path'],
            'default_save_path': config['default_save_path'],
            'jsonrpc_token': config.get('jsonrpc_token', 'token:')
        }
    })

@app.route('/api/test', methods=['GET', 'POST'])
def test_download():
    """测试下载接口"""
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'message': '测试接口',
            'usage': {
                'method': 'POST',
                'url': '/api/test',
                'data': {
                    'url': 'https://example.com/file.zip',
                    'filename': 'test.zip'
                }
            }
        })
    
    # 测试下载
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '需要测试数据'}), 400
        
        url = data.get('url', 'https://speed.hetzner.de/100MB.bin')
        filename = data.get('filename', 'test.bin')
        
        logger.info(f"测试下载: {url}")
        
        # 创建任务记录
        task_id = task_manager.add_task(url, config['default_save_path'], filename)
        
        # 执行下载
        task_manager.update_task(task_id, '处理中')
        success, message = call_idm(url, config['default_save_path'], filename)
        
        if success:
            task_manager.update_task(task_id, '已完成')
            return jsonify({
                'success': True,
                'message': '测试下载已启动',
                'task_id': task_id,
                'url': url,
                'save_path': config['default_save_path']
            })
        else:
            task_manager.update_task(task_id, '失败', message)
            return jsonify({
                'success': False,
                'error': message,
                'task_id': task_id
            }), 500
            
    except Exception as e:
        logger.error(f"测试下载失败: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/debug', methods=['GET'])
def debug_info():
    """调试信息"""
    tasks = task_manager.get_all_tasks(10)
    
    return jsonify({
        'success': True,
        'server_info': {
            'host': config['host'],
            'port': config['rpc_port'],
            'idm_path': config['idm_path'],
            'idm_exists': os.path.exists(config['idm_path']),
            'default_path': config['default_save_path'],
            'default_path_exists': os.path.exists(config['default_save_path'])
        },
        'recent_tasks': tasks,
        'log_file': log_file
    })

# 错误处理
@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404错误: {request.path}")
    return jsonify({'success': False, 'error': '接口不存在'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    logger.warning(f"405错误: {request.method} {request.path}")
    return jsonify({'success': False, 'error': '请求方法不允许'}), 405

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"400错误")
    return jsonify({'success': False, 'error': '请求数据格式不正确'}), 400

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500错误: {str(error)}", exc_info=True)
    return jsonify({'success': False, 'error': '服务器内部错误'}), 500

def start_server():
    """启动服务器"""
    print_startup_info()
    
    try:
        # 启动Flask服务器
        app.run(
            host=config['host'],
            port=config['rpc_port'],
            debug=config['debug'],
            threaded=True,
            use_reloader=False
        )
    except Exception as e:
        logger.error(f"服务器启动失败: {str(e)}", exc_info=True)
        print(f"\n服务器启动失败: {str(e)}")
        print("请检查:")
        print("1. 端口是否被占用（尝试修改rpc_port）")
        print("2. 防火墙是否阻止访问")
        print("3. 是否有其他程序正在使用该端口")
        input("\n按回车键退出...")

if __name__ == '__main__':
    start_server()