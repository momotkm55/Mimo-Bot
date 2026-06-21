# Mimo-Bot
— Проект на Rust с помощью которого можно запускать ботов (любое количество) на все сервера: Minecraft Pocket Edition 1.1.5

— Команда для запуска с одним ботом: ./target/release/bot -h play.example.com -p 19132 -n Steve
— Команда для запуска несколько ботов: ./target/release/bot -h play.example.com -p 19132 -n Steve --multi-bot --multi-bot-count 5

— Настройки логин-пакета есть в config.json

— Требования:
 • 1. Установить Rust: sudo apt update && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env" && sudo apt install -y build-essential pkg-config libssl-dev && rustc --version && cargo --version
 • 2. Скачать проект: git clone https://github.com/momotkm55/Mimo-Bot.git
 • 3. Собрать проект: cd Mimo-Bot-main && cargo build --release
 • 4. Запустить.

— Это форк проекта (https://github.com/zanderrroff/calvyn-mcpe-bot) от  zanderrroff.