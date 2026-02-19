docker compose up -d --build
docker exec -it ollama ollama pull gpt-oss:20b

curl http://localhost:11434/api/chat \        
  -H "content-type: application/json" \
  -d '{
    "model": "qwen2.5:3b",
    "stream": false,
    "messages": [{"role":"user","content":"Explain OAuth2 in 3 bullet points."}],
    "options": { "num_ctx": 1024, "num_predict": 128 }
  }'

curl -s http://localhost:3000/vector \               
  -H 'content-type: application/json' \
  -d '{ "model": "jmorgan/gte-small", "prompt": "Onions are round" }' | jq