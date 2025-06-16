FROM node:24.0-alpine AS build

ENV NODE_ENV=production

WORKDIR /app

RUN npm i -g pnpm

COPY package.json pnpm-lock.yaml ./

RUN pnpm --frozen-lockfile install

COPY . .

RUN pnpm build

####

FROM node:24.0-alpine

ENV HOST=0.0.0.0
ENV PORT=3000
ENV NODE_ENV=production

WORKDIR /app

RUN addgroup --system server && \
    adduser --system -G server server

RUN npm i -g pnpm

COPY --from=build /app/package.json \
  /app/pnpm-lock.yaml \
  ./

RUN pnpm --frozen-lockfile --prod install

COPY --from=build /app/dist ./

RUN chown -R server:server .

EXPOSE $PORT

CMD [ "node", "main.js" ]
