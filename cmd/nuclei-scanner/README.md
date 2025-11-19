# RedMantis Nuclei Scanner

Отдельный модуль для сканирования уязвимостей с помощью Nuclei на основе результатов RedMantis.

## Описание

Этот модуль:
- ✅ Читает `assets.json` (результаты RedMantis)
- ✅ Извлекает веб-сервисы (HTTP/HTTPS)
- ✅ Запускает Nuclei сканирование
- ✅ Объединяет результаты с исходными активами
- ✅ Сохраняет в `nuclei_assets.json` (не изменяет `assets.json`)

## Требования

1. **Nuclei должен быть установлен**:
   ```bash
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   nuclei -update-templates
   ```

2. **Файл `assets.json`** должен существовать (создается RedMantis сканером)

## Использование

### Сборка

```bash
cd cmd/nuclei-scanner
go build -o nuclei-scanner .
```

Или из корня проекта:

```bash
go build -o nuclei-scanner ./cmd/nuclei-scanner
```

### Запуск

```bash
./nuclei-scanner
```

Или из корня проекта:

```bash
./nuclei-scanner
```

## Конфигурация

Модуль использует настройки из `config.json`:

```json
{
  "nuclei": {
    "enabled": true,
    "severity": ["critical", "high", "medium"],
    "rate_limit": 10,
    "concurrency": 25,
    "timeout": "30s"
  }
}
```

**Важно**: Если `nuclei.enabled` установлен в `false`, модуль завершится с сообщением.

## Выходные данные

Результаты сохраняются в `nuclei_assets.json` в формате:

```json
[
  {
    "address": "192.168.1.100",
    "hostname": "example.local",
    "ports": [...],
    "nuclei_vulnerabilities": [
      {
        "template-id": "CVE-2021-44228",
        "matched-at": "http://192.168.1.100:8080",
        "info": {
          "name": "Log4j RCE",
          "severity": "critical",
          "tags": ["cve", "rce"]
        }
      }
    ]
  }
]
```

## Пример использования

```bash
# 1. Запустить RedMantis сканер
sudo ./redmantis

# 2. Запустить Nuclei сканер
./nuclei-scanner

# 3. Просмотреть результаты
cat nuclei_assets.json | jq '.[] | select(.nuclei_vulnerabilities != null)'
```

## Статистика

После завершения сканирования модуль выводит:
- Общее количество активов
- Количество активов с уязвимостями
- Общее количество найденных уязвимостей
- Распределение по уровням серьезности

## Примечания

- Модуль **не изменяет** исходный файл `assets.json`
- Результаты Nuclei добавляются в новое поле `nuclei_vulnerabilities`
- Если у актива нет уязвимостей, поле `nuclei_vulnerabilities` будет отсутствовать (или пустым)



