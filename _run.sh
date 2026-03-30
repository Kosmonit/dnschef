# python3 dnschef.py --nameservers 8.8.8.8 -i 0.0.0.0 --logfile dnslog.txt
TS="$(date +%Y-%m-%d_%H-%M-%S)"
LOG_DIR="log"
mkdir -p "${LOG_DIR}"
python3 dnschef.py --file dnschef.ini --nameservers 8.8.8.8 -i 0.0.0.0 --logfile "${LOG_DIR}/dnslog_${TS}.txt" --logfile-json "${LOG_DIR}/dnslog_${TS}.json"

