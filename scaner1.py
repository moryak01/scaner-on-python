import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
    6379: 'Redis', 27017: 'MongoDB'
}

def get_service_name(port):
    """Пытается получить название сервиса через системный сокет, иначе берет из словаря."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return COMMON_SERVICES.get(port, 'Unknown')

def scan_port(target, port, timeout):
    """Функция сканирования одного порта."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex бэкает 0, если порт открыт
            result = s.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                return port, service, True
    except Exception:
        pass
    return port, None, False

def parse_ports(port_string):
    """Парсит строку портов. Поддерживает форматы: '80', '80,443', '1-1000'."""
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="Быстрый многопоточный сканер портов")
    parser.add_argument("-t", "--target", required=True, help="Целевой IP или домен")
    parser.add_argument("-p", "--ports", default="21,22,80,443,8080", 
                        help="Порты для сканирования (например: 80 или 1-1000 или 22,80,443)")
    parser.add_argument("-T", "--threads", type=int, default=100, 
                        help="Количество потоков (по умолчанию: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, 
                        help="Таймаут подключения в секундах (по умолчанию: 1.0)")
    
    args = parser.parse_args()
    
    target = args.target
    ports = parse_ports(args.ports)
    threads = args.threads
    timeout = args.timeout

    print("-" * 50)
    print(f"Начало сканирования: {target}")
    print(f"Порты: {len(ports)} | Потоки: {threads} | Таймаут: {timeout}s")
    print(f"Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    # резолв хост в ip-адрес
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n[!] Ошибка: Не удалось разрешить имя хоста '{target}'")
        sys.exit(1)

    open_ports = []
    start_time = datetime.now()

    try:
        # многопоточное сканирование
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Создаем задачи для каждого порта
            futures = {executor.submit(scan_port, target_ip, port, timeout): port for port in ports}
            
            # сбор результатов по мере их выполнения
            for future in as_completed(futures):
                port, service, is_open = future.result()
                if is_open:
                    open_ports.append((port, service))
                    
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем.")
        sys.exit(0)

    # сортировка открытых портов по возрастанию
    open_ports.sort(key=lambda x: x[0])

    # вывод результата
    print("\n" + "=" * 50)
    print(f"{'ПОРТ':<10} | {'СОСТОЯНИЕ':<10} | {'СЕРВИС'}")
    print("-" * 50)
    
    if open_ports:
        for port, service in open_ports:
            print(f"{port:<10} | {'OPEN':<10} | {service}")
    else:
        print("Открытых портов не найдено.")
        
    print("=" * 50)
    print(f"Сканирование завершено за: {datetime.now() - start_time}")

if __name__ == "__main__":
    main()