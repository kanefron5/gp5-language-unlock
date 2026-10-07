# Valeton GP-5: разблокировка английского

Патчер официальной USB-прошивки **1.0.6** для китайской GP-5. Меняет одну инструкцию: вместо заводской маски языков возвращает `3`, разрешающую English и Chinese. Пересчитывает CRC блока и файла; проверки CRC остаются включены.

**Проверено 7 октября 2026 на одной GP-5:** запись прошла, английский сохраняется после перезапуска, Valeton Suite на iOS тоже работает на английском. На других экземплярах и версиях прошивки не проверено.

## Требования

- Python 3.9+. Патчер без зависимостей работает на macOS, Windows и Linux.
- Для записи: macOS, ARM64 Python на Apple Silicon и установленный Valeton Suite 2.1.0 с проверенной библиотекой.
- [Официальная GP-5 USB V1.0.6](https://valeton.oss-accelerate.aliyuncs.com/update/gp-5/pkg/GP-5_USB_V1.0.6_20250626.bin), распакованная и сохранённая как `firmware.bin`.
- SHA-256 оригинала: `259ac4e77d3df792ff48e55feff52427ff2ea9ed63cb65785360a23a10dbaf42`.

## Патч и проверка

```sh
python3 gp5_language_patch.py patch firmware.bin -o firmware_languages.bin
python3 gp5_diag.py check firmware_languages.bin
python3 gp5_diag.py native-crc firmware_languages.bin
```

Ожидается `valid: true` и `checkCrc return_code: 0`. SHA-256 результата: `6373ccee45d5e8689d4d061700d138d2b6aabdbcfa317702876f9c36a2ce2bf2`.

## Запись

Закрыть Valeton Suite, подключить педаль по USB. Из обычного режима:

```sh
python3 gp5_diag.py native-flash firmware_languages.bin --enter-update --announce-version V999 --version-reject-ok --trace-midi
```

Если педаль уже вручную включена в загрузчик, заменить `--enter-update` на `--bootloader --suite-handshake`.

Дождаться `flash_finished` и итогового статуса `0`, питание во время записи не отключать. После загрузки выбрать English и проверить сохранение после перезапуска.

`V999` объявляется только в команде обмена с загрузчиком. Версия файла и устройства остаётся **1.0.6**. Повторная запись официального оригинала убирает патч. Гарантии восстановления при любой неисправности нет.

## Восстановление файла

```sh
python3 gp5_language_patch.py restore firmware_languages.bin -o firmware_restored.bin
```

Восстанавливает оригинальный файл побайтно, устройство не затрагивает. Патчер отклоняет другие прошивки и не перезаписывает существующие файлы.

Подробности инструкции, CRC, мобильной синхронизации и найденного механизма активации языков: [docs/RESEARCH.md](docs/RESEARCH.md). Активационный код не используется этим патчем; рабочий генератор такого кода пока не подготовлен.
