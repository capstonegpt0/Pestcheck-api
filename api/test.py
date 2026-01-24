from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from .models import PestDetection, PestInfo

User = get_user_model()


class UserAuthenticationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = '/api/auth/register/'
        self.login_url = '/api/auth/login/'
        
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
            'password_confirm': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User'
        }
    
    def test_user_registration(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
    
    def test_user_login(self):
        # Create user first
        User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        login_data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)


class PestDetectionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
    
    def test_list_detections(self):
        response = self.client.get('/api/detections/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_geofence_validation(self):
        # Test with coordinates outside Magalang
        detection_data = {
            'crop_type': 'rice',
            'latitude': 14.5995,  # Manila coordinates
            'longitude': 120.9842,
        }
        # This should fail validation
        # Actual test would need image upload


class PestInfoTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        
        self.pest = PestInfo.objects.create(
            name='Test Pest',
            scientific_name='Testus pestus',
            crop_affected='rice',
            description='Test description',
            symptoms='Test symptoms',
            control_methods='Test control',
            prevention='Test prevention'
        )
    
    def test_list_pests(self):
        response = self.client.get('/api/pests/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    def test_search_pests(self):
        response = self.client.get('/api/pests/search/?q=Test')
        self.assertEqual(response.status_code, status.HTTP_200_OK)