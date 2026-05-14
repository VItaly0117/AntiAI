# Документація драйвера AntiAIKernel

## 1. Призначення

Проект AntiAIKernel призначений для створення інфраструктури виявлення та блокування діяльності штучного інтелекту на рівні операційної системи Windows. Поточна версія MVP реалізує базовий каркас драйвера режиму ядра, IOCTL-інтерфейс для керування режимами роботи, а також користувацькі компоненти для адміністрування та моніторингу. Система розроблена з дотриманням принципів прозорості та відсутності прихованої функціональності.

## 2. Архітектура

Архітектура системи побудована за принципом клієнт-сервер з використанням драйвера режиму ядра та користувацьких компонентів. Основні шари архітектури:

- **Kernel Layer**: Драйвер AntiAIKernel.sys (KMDF) створює пристрій `\Device\AntiAIKernel` та символьне посилання `\DosDevices\AntiAIKernel` для взаємодії з користувацьким режимом (шлях у користувацькому режимі: `\\.\AntiAIKernel`)
- **User Layer**: Анти-AI сервіс (AntiAIService.exe) забезпечує періодичний опитування драйвера та логування стану через OutputDebugString
- **Control Interface**: Утиліта AntiAIControl.exe надає інтерфейс для адміністрування через командний рядок
- **Shared Layer**: Спільні заголовкові файли (antiai_policy.h, antiai_ioctl.h) визначають інтерфейс між драйвером та користувацькими компонентами

Комунікація між драйвером та користувацькими компонентами здійснюється через IOCTL-інтерфейс.

## 3. Компоненти

### 3.1 AntiAIKernel.sys

Ядерний драйвер Windows (KMDF), що виконує такі функції:
- Створення пристрою `\Device\AntiAIKernel` та символьного посилання `\DosDevices\AntiAIKernel`
- Обробка IOCTL-запитів PING, GET_VERSION, GET_STATUS, SET_MODE, GET_MODE
- Збереження поточного режиму роботи в пам'яті драйвера
- Реалізація виявлення та блокування процесів fake_ai_tool.exe та ollama.exe через process_guard.c
- Реєстрація в системі як стандартний драйвер без прихованої функціональності

### 3.2 AntiAIControl.exe

Консольна утиліта адміністрування, що забезпечує:
- Перевірку доступності драйвера (команда `ping`)
- Отримання версії драйвера (команда `version`)
- Отримання статусу драйвера (команда `status`)
- Тестування IOCTL інтерфейсу (команда `test`)
- Встановлення режиму роботи драйвера (команда `mode off|audit|block-network|block-process|block-all`)
- Додавання IP-адреси в блок-лист (команда `add-ip <IP>`)
- Додавання домену в блок-лист (команда `add-domain <domain>`)
- Очищення мережевих правил (команда `clear-network-rules`)

### 3.3 AntiAIService.exe

Сервіс Windows / консольний монітор, що виконує функції:
- Періодичне опитування драйвера кожні 30 секунд
- Логування поточного режиму та стану драйвера через OutputDebugString
- Підтримка режиму роботи як Windows service або консольної програми

### 3.4 AntiAIWfp

Користувацький модуль Windows Filtering Platform (WFP), що виконує функції:
- Реалізація user-mode WFP API helper для мережевої фільтрації
- Блокування мережевих з'єднань до AI-сервісів через WFP callout-функції
- Управління блок-листом доменів та IP-адрес
- Інтеграція з драйвером через IOCTL для синхронізації правил

### 3.5 Shared

Спільний модуль, що містить:
- `antiai_ioctl.h`: визначення IOCTL кодів та структур даних
- `antiai_policy.h`: константи режимів роботи та політики

## 4. Режими роботи

Система підтримує п'ять режимів роботи на рівні драйвера:

### 4.1 OFF (0)
Драйвер завантажений, але функції блокування відключені. Моніторинг не виконується.

### 4.2 AUDIT_ONLY (1)
Режим лише аудиту без блокування. Виявлення AI-сервісів та ML-процесів з логуванням без переривання діяльності.

### 4.3 BLOCK_NETWORK (2)
Режим блокування мережевих з'єднань. Блокування трафіку до AI-сервісів через user-mode WFP helper (AntiAIWfp). Локальні ML-процеси продовжують роботу.

### 4.4 BLOCK_PROCESS (3)
Режим блокування локальних процесів. Переривання процесів fake_ai_tool.exe та ollama.exe через process_guard.c. Мережевий трафік не фільтрується.

### 4.5 BLOCK_ALL (4)
Комплексний режим захисту. Блокування мережевих з'єднань до AI-сервісів через WFP та блокування локальних ML-процесів.

## 5. IOCTL API

Драйвер надає наступний IOCTL-інтерфейс:

```c
#define IOCTL_ANTIAI_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_SET_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### 5.1 IOCTL_ANTIAI_PING
Призначення: перевірка доступності драйвера

Вхідний буфер: відсутній

Вихідний буфер: відсутній

### 5.2 IOCTL_ANTIAI_GET_VERSION
Призначення: отримання версії драйвера

Вхідний буфер: відсутній

Вихідний буфер:
```c
typedef struct _ANTI_AI_VERSION {
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
} ANTI_AI_VERSION, *PANTI_AI_VERSION;
```

### 5.3 IOCTL_ANTIAI_GET_STATUS
Призначення: отримання статусу драйвера

Вхідний буфер: відсутній

Вихідний буфер:
```c
typedef struct _ANTI_AI_STATUS {
    ULONG CurrentMode;
    ULONG DriverState;
    ULONG Reserved[2];
} ANTI_AI_STATUS, *PANTI_AI_STATUS;
```

### 5.4 IOCTL_ANTIAI_SET_MODE
Призначення: встановлення режиму роботи драйвера

Вхідний буфер:
```c
typedef struct _ANTI_AI_MODE {
    ULONG Mode; // 0=OFF, 1=AUDIT_ONLY, 2=BLOCK_NETWORK, 3=BLOCK_PROCESS, 4=BLOCK_ALL
} ANTI_AI_MODE, *PANTI_AI_MODE;
```

Вихідний буфер: відсутній

### 5.5 IOCTL_ANTIAI_GET_MODE
Призначення: отримання поточного режиму драйвера

Вхідний буфер: відсутній

Вихідний буфер:
```c
typedef struct _ANTI_AI_MODE {
    ULONG Mode; // 0=OFF, 1=AUDIT_ONLY, 2=BLOCK_NETWORK, 3=BLOCK_PROCESS, 4=BLOCK_ALL
} ANTI_AI_MODE, *PANTI_AI_MODE;
```

## 6. Мережеве блокування AI-сервісів через WFP

Мережеве блокування реалізовано через Windows Filtering Platform (WFP) як user-mode helper (AntiAIWfp), а не як kernel callout. Цей підхід забезпечує гнучкість та простоту розробки.

Алгоритм роботи:
1. Користувацький модуль AntiAIWfp ініціалізує WFP сесію та додає фільтри
2. Кожна спроба з'єднання перехоплюється WFP callout-функцією
3. Доменне ім'я або IP-адреса порівнюється зі списком правил
4. При збігу з'єднання блокується (повертається FWP_ACTION_BLOCK)
5. Подія логується через OutputDebugString

Список AI-сервісів за замовчуванням:
- api.openai.com
- anthropic.com
- cohere.com
- huggingface.co
- replicate.com
- together.ai
- mistral.ai

## 7. Локальне виявлення ML-процесів через process creation callback

Для виявлення локальних ML-процесів драйвер використовує callback-функцію моніторингу створення процесів (PsSetCreateProcessNotifyRoutineEx), реалізовану в process_guard.c.

Алгоритм роботи:
1. При завантаженні драйвер реєструє callback-функцію
2. При створенні нового процесу викликається callback
3. Ім'я процесу порівнюється зі списком відомих AI-інструментів:
   - fake_ai_tool.exe
   - ollama.exe
4. При виявленні ML-процесу в залежності від режиму:
   - AUDIT_ONLY: логування події
   - BLOCK_PROCESS або BLOCK_ALL: переривання процесу через ZwTerminateProcess
5. Подія логується з деталями (PID, ім'я, шлях)

## 8. Як зібрати

### Вимоги до середовища розробки:
- Windows Driver Kit (WDK) 10 або 11
- Visual Studio 2019 або 2022 з робочим навантаженням "Desktop development with C++"
- Windows SDK

### Інструкція зі зборки:

1. Відкрити рішення `AntiAI.sln` у Visual Studio
2. Вибрати конфігурацію:
   - Debug для налагодження
   - Release для production
3. Вибрати платформу: x64
4. Натиснути Build -> Build Solution (Ctrl+Shift+B)

Результати зборки:
- `AntiAIKernel\x64\Release\AntiAIKernel.sys` - драйвер
- `AntiAIControl\x64\Release\AntiAIControl.exe` - утиліта керування
- `AntiAIService\x64\Release\AntiAIService.exe` - сервіс

## 9. Як встановити test-signed driver

Для встановлення драйвера в режимі тестового підпису виконайте наступні кроки:

### 9.1 Увімкнення тестового режиму підпису

Відкрийте Command Prompt від імені адміністратора та виконайте:

```cmd
bcdedit /set testsigning on
```

Перезавантажте систему.

### 9.2 Підписання драйвера тестовим сертифікатом

Створіть тестовий сертифікат (якщо відсутній):

```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=AntiAITestCert" AntiAITestCert.cer
certmgr /add AntiAITestCert.cer /s /r localMachine root
```

Підпишіть драйвер:

```cmd
signtool sign /v /s PrivateCertStore /n "AntiAITestCert" AntiAIKernel.sys
```

### 9.3 Встановлення драйвера

Використовуйте утиліту SC (Service Control):

```cmd
sc create AntiAIKernel type= kernel binPath= "C:\path\to\AntiAIKernel.sys"
sc start AntiAIKernel
```

## 10. Як перевірити

### 10.1 Перевірка завантаження драйвера

```cmd
sc query AntiAIKernel
```

Очікуваний статус: RUNNING

### 10.2 Перевірка IOCTL інтерфейсу через AntiAIControl

Перевірка доступності драйвера:
```cmd
AntiAIControl.exe ping
```

Отримання версії драйвера:
```cmd
AntiAIControl.exe version
```

Отримання статусу драйвера:
```cmd
AntiAIControl.exe status
```

Тестування IOCTL інтерфейсу:
```cmd
AntiAIControl.exe test
```

Встановлення режиму AUDIT_ONLY:
```cmd
AntiAIControl.exe mode audit
```

Встановлення режиму BLOCK_NETWORK:
```cmd
AntiAIControl.exe mode block-network
```

Встановлення режиму BLOCK_PROCESS:
```cmd
AntiAIControl.exe mode block-process
```

Встановлення режиму BLOCK_ALL:
```cmd
AntiAIControl.exe mode block-all
```

Встановлення режиму OFF:
```cmd
AntiAIControl.exe mode off
```

Додавання IP-адреси в блок-лист:
```cmd
AntiAIControl.exe add-ip 1.2.3.4
```

Додавання домену в блок-лист:
```cmd
AntiAIControl.exe add-domain example.com
```

Очищення мережевих правил:
```cmd
AntiAIControl.exe clear-network-rules
```

### 10.3 Перевірка роботи AntiAIService

Запуск в консольному режимі:
```cmd
AntiAIService.exe console
```

Очікуваний результат: сервіс опитує драйвер кожні 30 секунд та виводить лог через OutputDebugString

## 11. Обмеження MVP

Поточна версія MVP має наступні обмеження:

- **IOCTL інтерфейс**: реалізовано PING, GET_VERSION, GET_STATUS, SET_MODE, GET_MODE; ADD_RULE, REMOVE_RULE, GET_LOG не реалізовано
- **Виявлення процесів**: реалізовано лише для fake_ai_tool.exe та ollama.exe; розширення списку ML-фреймворків не реалізовано
- **Мережеве блокування**: реалізовано як user-mode WFP helper (AntiAIWfp), а не як kernel callout
- **Логування**: відсутній системний буфер логів; логування виконується через OutputDebugString в AntiAIService
- **Правила блокування**: механізм додавання/видалення правил через IOCTL не реалізовано; управління правилами виконується через AntiAIControl
- **Платформа**: підтримка тільки x64 Windows 10/11

## 12. Безпека

Система AntiAIKernel розроблена з дотриманням принципів прозорості та безпеки:

### 12.1 Відсутність руткіта
- Драйвер не приховує своє присутність в системі
- Відображається в списку драйверів (driverquery)
- Відсутні техніки rootkit (DKOM, SSDT hooking, inline hooking)
- Пристрій `\Device\AntiAIKernel` та символьне посилання `\DosDevices\AntiAIKernel` створюються відкрито

### 12.2 Відсутність інжектів
- Драйвер не виконує код-інжекцію в користувацькі процеси
- Відсутні модифікації пам'яті процесів
- Відсутні DLL-інжекти або APC-інжекти

### 12.3 Відсутність прихованої персистентності
- Драйвер встановлюється через стандартний механізм SCM
- Відсутні приховані реєстраційні ключі
- Відсутні техніки стелс-персистентності
- Драйвер може бути повністю видалений через `sc delete AntiAIKernel`

### 12.4 Відсутність обходу захисту
- Драйвер не намагається обійти системні механізми захисту
- Відсутні спроби відключення антивірусного ПЗ
- Дотримується стандартних API Windows

### 12.5 Прозорість
- Весь код відкритий для аудиту
- Відсутність прихованої функціональності
- Можливість повного видалення драйвера без залишкових артефактів

## 13. Подальший розвиток

Плани розвитку проекту включають:

### 13.1 Розширення списку виявлення ML-процесів
- Додавання підтримки інших AI-інструментів та ML-фреймворків
- Аналіз завантажених DLL для виявлення ML-бібліотек
- Моніторинг використання GPU (CUDA, DirectML)
- Виявлення характерних патернів поведінки ML-процесів

### 13.2 Покращення мережевої фільтрації
- Динамічне оновлення списку AI-сервісів
- Виявлення спроб обходу через проксі/VPN
- Фільтрація TLS-трафіку з розпізнаванням SNI
- Інтеграція з системними брандмауерами

### 13.3 Розширення IOCTL інтерфейсу
- Реалізація IOCTL_ANTIAI_ADD_RULE для додавання правил блокування
- Реалізація IOCTL_ANTIAI_REMOVE_RULE для видалення правил
- Реалізація IOCTL_ANTIAI_GET_LOG для отримання журналу подій
- Розширення структури ANTI_AI_STATUS для отримання детальної статистики

### 13.4 Покращення логування
- Реалізація системного буфера логів в драйвері
- Ротація логів
- Інтеграція з системним журналом подій Windows

### 13.5 Розширення платформи
- Підтримка ARM64 архітектури
- Підтримка Windows Server
- Підтримка старіших версій Windows

---

**Версія документації**: 1.0  
**Дата**: травень 2026  
**Автор**: команда розробки AntiAIKernel
