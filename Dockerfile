FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

# Instalar TODAS las dependencias (incluyendo devDependencies para build)
RUN npm install

COPY . .

# Compilar Tailwind CSS para producción
RUN npm run build:css

# Eliminar devDependencies después del build para imagen más ligera
RUN npm prune --production

# Crear directorios necesarios
RUN mkdir -p uploads/chunks

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["npm", "start"]
