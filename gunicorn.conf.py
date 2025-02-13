import multiprocessing

# Gunicorn configuration file
bind = "0.0.0.0:10000"  # Use port 10000 as per Render's requirements
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
worker_class = "sync"
preload_app = True

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"