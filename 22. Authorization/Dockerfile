# используем официальный образ питона
FROM python:3.9-slim

#устанавливаем рабочую директорию в контейнере
WORKDIR /app

#копируем файл зависимостей
COPY requirements.txt .

#устанавливаем зависимости из этого файла
RUN pip install --no-cache-dir -r requirements.txt

#копируем все содержимое папки в контейнер
COPY . .

#указываем команду для запуска сервера unicorn

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
