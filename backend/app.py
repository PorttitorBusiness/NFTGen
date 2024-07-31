from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import tensorflow as tf
from tensorflow import keras
from PIL import Image
import numpy as np
import io
import base64
import os
from dotenv import load_dotenv
from laminas_api_tools import ApiTools, ApiResource, ApiResponse, RequestParser, fields

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configurations from environment variables
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

# Initialize Laminas API Tools
api = ApiTools(app)

# Load the model
model_path = os.getenv('MODEL_PATH')
model = keras.models.load_model(model_path)

class LoginResource(ApiResource):
    def post(self):
        parser = RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username = args['username']
        password = args['password']
        # Verifique o usuário e a senha no banco de dados
        access_token = create_access_token(identity=username)
        return ApiResponse({'access_token': access_token})

class GenerateNFTResource(ApiResource):
    @jwt_required()
    def post(self):
        parser = RequestParser()
        parser.add_argument('data', type=dict, required=True, help='Data is required')
        args = parser.parse_args()

        data = args['data']
        # Lógica para gerar o NFT usando IA
        nft_image = generate_nft_logic(data)
        return ApiResponse({"image": nft_image})

class ValidateNFTResource(ApiResource):
    def post(self):
        parser = RequestParser()
        parser.add_argument('token_id', type=str, required=True, help='Token ID is required')
        parser.add_argument('metadata', type=dict, required=True, help='Metadata is required')
        args = parser.parse_args()

        token_id = args['token_id']
        metadata = args['metadata']
        is_valid = validate_nft_logic(token_id, metadata)
        return ApiResponse({"is_valid": is_valid})

def generate_nft_logic(data):
    noise = np.random.normal(0, 1, (1, 100))  # Supondo que a entrada do modelo GAN seja um vetor de 100 dimensões
    generated_image = model.predict(noise)
    
    # Convertendo a imagem gerada para base64
    image = (generated_image * 127.5 + 127.5).astype(np.uint8)
    image = Image.fromarray(image[0])
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return img_str

def validate_nft_logic(token_id, metadata):
    if not token_id or not re.match(r'^[0-9a-fA-F]{64}$', token_id):
        return False
    if not metadata or not isinstance(metadata, dict):
        return False
    return True

# Register API resources
api.add_resource(LoginResource, '/api/v1/login')
api.add_resource(GenerateNFTResource, '/api/v1/generate-nft')
api.add_resource(ValidateNFTResource, '/api/v1/validate-nft')

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG') == '1')
