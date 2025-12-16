FROM ruby:2.6
WORKDIR /app
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD ["ruby", "api_server.rb"]
