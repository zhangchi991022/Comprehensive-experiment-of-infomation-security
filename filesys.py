import time

from watchdog.events import *
from watchdog.observers import Observer

import configparser
import os

from threading import Thread
import subprocess

class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        FileSystemEventHandler.__init__(self)

    def on_moved(self, event):
        if event.is_directory:
            print("目录移动从{0}到{1}".format(event.src_path, event.dest_path))
        else:
            print("文件移动从{0}到{1}".format(event.src_path, event.dest_path))

    def on_created(self, event):
        if event.is_directory:
            print("目录创建:{0}".format(event.src_path))
        else:
            print("文件创建:{0}".format(event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            print("目录删除:{0}".format(event.src_path))
        else:
            print("文件删除:{0}".format(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            pass
        else:
            print("文件修改:{0}".format(event.src_path))
            
conf= configparser.ConfigParser()
def readConf():
    '''读取配置文件'''
    conf.read('config.conf')  # 文件路径
    list = conf.get("directory","pathlist").split(',')  # 获取指定section 的option值
    return list

if __name__ == "__main__":
    pathlist = readConf()
    for path in pathlist:
        observer1 = Observer()
        event_handler = FileEventHandler()

        observer1.schedule(event_handler, path , True)
        observer1.start()
     
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer1.stop()
    observer1.join()
    

    
