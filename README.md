# Mimo-Bot

Проект на Rust для запуска ботов (любое количество) на серверы Minecraft Pocket Edition 1.1.5

## Запуск

Один бот:
```bash
./target/release/bot -h play.example.com -p 19132 -n Steve
```

Несколько ботов:
```bash
./target/release/bot -h play.example.com -p 19132 -n Steve --multi-bot --multi-bot-count 5
```

Настройки логин-пакета находятся в `config.json`

## Установка

1. Установить Rust:
```bash
sudo apt update && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env" && sudo apt install -y build-essential pkg-config libssl-dev
```
2. Скачать проект:
```bash
git clone https://github.com/momotkm55/Mimo-Bot.git
```
3. Собрать проект:
```bash
cd Mimo-Bot-main && cargo build --release
```
4. Запустить.

## Форк
Основан на проекте [calvyn-mcpe-bot](https://github.com/zanderrroff/calvyn-mcpe-bot) от zanderrroff.
