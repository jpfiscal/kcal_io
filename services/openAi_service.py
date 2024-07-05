from dotenv import load_dotenv
from openai import OpenAI

import openai
import os
import base64
import requests

def generate_auth_code(client_id, client_secret):
    auth_string = f"{client_id}:{client_secret}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')
    return f"Basic {base64_string}"

def get_kcal_in_est(image_path):
    load_dotenv()

    api_key = os.getenv("OPENAI_API_KEY")

    if api_key is None:
        raise ValueError("No API key found. Please set OPENAI_API_KEY in the .env file.")

    openai.api_key = api_key

    def encode_image(image_path):
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
        
    # image_path = f"upload_imgs/{filename}"

    base64_image = encode_image(image_path)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
            "role": "user",
            "content": [
                {
                "type": "text",
                "text": "Please give me the name of the food in the attached image with JUST the name of the food and the macronutrient content in the following format: {\"name\": \"<name of food>\", \"calories\": <calories in kcal>, \"protein\": <Protein count in grams>, \"fat\": <Fat count in grams>, \"carbs\": <Carbohydrates count in grams>}. For numeric values like calories, carbs, fat, and protein, just provide the number but not the units. If the image doesn't look like any kind of food, respond with this exact string: No food was recognized from the image you provided."
                },
                {
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/jpeg;base64,{base64_image}"
                }
                }
            ]
            }
    ],
    "max_tokens": 300
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    response_data = response.json()
    content = response_data['choices'][0]['message']['content']
    return content