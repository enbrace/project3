from scapy.all import *
import csv
from datetime import datetime

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

# 创建 CSV 文件并写入表头
with open('network_traffic_log.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["时间", "源 MAC", "源 IP", "目标 MAC", "目标 IP", "帧长度"])

def packet_callback(pkt):
    if Ether in pkt and IP in pkt:
        # 提取 MAC 和 IP 地址
        src_mac = pkt[Ether].src
        src_ip = pkt[IP].src
        dst_mac = pkt[Ether].dst
        dst_ip = pkt[IP].dst
        frame_length = len(pkt)
        # 获取当前时间
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 写入 CSV
        with open('network_traffic_log.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_mac, src_ip, dst_mac, dst_ip, frame_length])

# 开始抓包
sniff(prn=packet_callback, store=0)
