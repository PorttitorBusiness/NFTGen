# Use uma imagem oficial do Python como base
FROM python:3.9-slim

# Defina o diretório de trabalho
WORKDIR /app

# Copie o arquivo requirements.txt e instale as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie o restante do código do aplicativo
COPY . .

# Exponha a porta que o Flask usará
EXPOSE 8000

# Comando para rodar a aplicação usando Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
