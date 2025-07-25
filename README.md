# DeepCode

DeepCode — это лёгкий и гибкий CLI-инструмент на основе LLM, который предлагает функциональность уровня Claude Code, но работает с любыми моделями, без ограничений по тарифам и с полной настраиваемостью.

## Возможности

- Генерация кода (флаг `-c/--coding-only`).
- Автоматический workflow (флаг `-w/--auto-workflow`):
  1. Генерирует решение.
  2. Запускает авто-дебаг до 10 итераций, включая GUI-приложения.
  3. Валидирует выполнение.
  4. Формирует JSON-отчёт.
- Поддержка GUI-проектов (Tkinter, PyQt5, etc.) в headless-режиме.
- Автоматическое создание `.venv` и `pip install` недостающих пакетов.
- Поддержка unified-diff патчей: ИИ может изменять существующие файлы.
- Защита: чёрный список опасных команд, ограничение размеров файлов, виртуальное окружение.

## Установка

```bash
# Клонируйте репозиторий
git clone https://github.com/rafabduloff/deepcode
cd deepcode

# Создайте .env на основе шаблона (env.dev содержит все переменные)
cp env.dev .env
# затем вставьте ваш ключ OpenRouter
vim .env   # или nano .env

# Установите Python 3.11+ и зависимости
python3.11 -m pip install -r requirements.txt
```

> **Требования**: Python **3.11** или новее, Linux/macOS/WSL.
>
> GUI-функции убраны — инструмент теперь ориентирован на консольные задачи.

### Быстрый alias

Чтобы не писать полный путь, добавьте в `~/.zshrc` или `~/.bashrc`:

```bash
alias ai="python ~/deepcode/askgpt.py"
```

Перезагрузите шелл (`source ~/.zshrc`) и используйте команду `ai` во всех примерах ниже.

## Быстрый старт

```bash
# Сгенерировать пример кода и запустить
aі -c "Создай скрипт калькулятора"

# Полный workflow с отчётом
aі -w --workflow-output report.json \
  "Напиши игру крестики-нолики и протестируй её"
```

## Ключевые флаги

| Флаг                                              | Описание                                    |
| ------------------------------------------------- | ------------------------------------------- |
| `-c`, `--coding-only`                             | Генерация кода + (опц.) запуск              |
| `-w`, `--auto-workflow`                           | Полный цикл код→дебаг→валидация             |
| `--init [files]`                                  | Загрузить контекст существующих файлов      |
| `--analyze`, `--refactor`, `--test`, `--document` | Другие режимы                               |
| `-a`, `--auto-execute`                            | Не спрашивать подтверждение команд          |
| `--max-debug-iterations`                          | Сколько проходов авто-дебага (по умолч. 10) |
| `--model`, `--max-tokens`                         | Параметры LLM вызыва                        |

Полный список — `ai -h`.

## Конфигурация

Все настройки хранятся в `.ai_agent_config.json` (создаётся автоматически):

```json
{
  "auto_execute": false,
  "ignored_dirs": [".git", "__pycache__", "node_modules", ".venv", "venv"],
  "max_debug_iterations": 10,
  "use_venv": true,
  "auto_install": true
}
```

Менять можно через команду:

```bash
ai --config max_debug_iterations 5
```

## Безопасность

Инструмент фильтрует опасные команды (rm -rf, curl …, ssh …). При необходимости расширьте массив `BLACKLIST` в `askgpt.py`.

## Как работает авто-дебаг

1. Скрипт пытается запустить программу.
2. При неудаче анализирует ошибку и посылает LLM запрос с текстом ошибки.
3. LLM возвращает фикс **либо** unified-diff.
4. Скрипт применяет изменения, при необходимости устанавливает недостающие модули (`pip install`).
5. Повторяет до 10 раз или до успеха.

## Формат отчёта

`report_*.json` содержит:

```json
{
  "query": "…",            # исходный запрос
  "generated_files": ["…"],
  "steps": [                 # ход workflow
    {"step": "code_generation", "files": ["…"]},
    {"step": "debug_file.py", "success": true}
  ],
  "validation": [            # итоговая проверка
    {"file": "file.py", "success": true, "stdout": "…"}
  ],
  "timestamp": "2025-06-28T12:34:56"
}
```

## Чат-режим

Запуск:

```bash
ai          # интерактивный чат (по умолчанию)
ai --chat   # то же самое
```

Команды внутри REPL:

| Команда           | Действие                             |
| ----------------- | ------------------------------------ |
| `:help`           | показать подсказку                   |
| `:exit` / `:quit` | выйти                                |
| `:reset`          | очистить контекст                    |
| `:save [file]`    | сохранить историю в JSON             |
| `:load <file>`    | загрузить историю из JSON            |
| `:list`           | показать список сохранённых сессий   |
| `:open <N>`       | открыть сессию по номеру (из списка) |

Истории сохраняются автоматически в `~/ai/chats/` после каждой реплики.

---

## Переключение моделей LLM

Доступны два профиля:

| Псевдоним | Модель                                |
| --------- | ------------------------------------- |
| **fast**  | `deepseek/deepseek-chat-v3-0324:free` |
| **power** | `deepseek/deepseek-r1:free`           |

Режим по умолчанию хранится в `.env` (ключ `OPENROUTER_MODEL_MODE`). Управление:

```bash
ai --model-mode fast    # навсегда переключиться на fast
ai --model-mode power   # на power
ai --model-mode auto    # авто-выбор (эвристика)

ai --show-model         # показать текущую настройку
```

---

Наслаждайтесь
