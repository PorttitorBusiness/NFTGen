# Use uma imagem oficial do Node.js como base
FROM node:14

# Defina o diretório de trabalho
WORKDIR /app

# Copie o package.json e instale as dependências
COPY package.json .
RUN npm install

# Copie o restante do código do aplicativo
COPY . .

# Construa o aplicativo Angular
RUN npm run build --prod

# Use uma imagem oficial do Nginx para servir o aplicativo Angular
FROM nginx:alpine

# Copie os arquivos construídos do Angular para o diretório padrão do Nginx
COPY --from=0 /app/dist/nft-generator /usr/share/nginx/html

# Exponha a porta que o Nginx usará
EXPOSE 80

# Comando para rodar o Nginx
CMD ["nginx", "-g", "daemon off;"]
