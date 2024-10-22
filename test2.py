import datetime  # 保持原来的导入
import csv
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

def ftp_packet_callback(pkt):
    if TCP in pkt and pkt[TCP].dport == 21:
        if Raw in pkt:
            data = pkt[Raw].load.decode(errors='ignore')
            if "USER" in data or "PASS" in data:
                # 解析用户和密码
                user = data.split("USER ")[1].split()[0] if "USER" in data else ""
                password = data.split("PASS ")[1].split()[0] if "PASS" in data else ""
                success = "SUCCEED" if "230" in data else "FAILED" if "530" in data else ""
                # 获取当前时间和地址信息
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 修改此行
                src_mac = pkt[Ether].src
                src_ip = pkt[IP].src
                dst_mac = pkt[Ether].dst
                dst_ip = pkt[IP].dst
                # 写入 CSV
                with open('ftp_login_log.csv', mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([timestamp, src_mac, src_ip, dst_mac, dst_ip, user, password, success])

# 开始监听 FTP 数据
sniff(prn=ftp_packet_callback, filter='tcp port 21', store=0)
