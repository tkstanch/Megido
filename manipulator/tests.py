from django.test import TestCase
from django.core.management import call_command
from manipulator.models import VulnerabilityType, Payload, EncodingTechnique, PayloadManipulation
from io import StringIO


class PopulateManipulatorDataTest(TestCase):
    """Test the populate_manipulator_data management command"""
    
    def test_command_runs_successfully(self):
        """Test that the command runs without errors"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        output = out.getvalue()
        
        # Check that the command completed successfully
        self.assertIn('Initial data population complete!', output)
        self.assertIn('Summary:', output)
    
    def test_vulnerability_types_created(self):
        """Test that vulnerability types are created"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        
        # Check that vulnerability types exist
        self.assertTrue(VulnerabilityType.objects.filter(name='XSS').exists())
        self.assertTrue(VulnerabilityType.objects.filter(name='SQLi').exists())
        self.assertTrue(VulnerabilityType.objects.filter(name='LFI').exists())
    
    def test_payloads_created(self):
        """Test that payloads are created"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        
        # Check that some payloads exist
        self.assertTrue(Payload.objects.count() > 0)
        
        # Check for specific payloads
        xss_vuln = VulnerabilityType.objects.get(name='XSS')
        self.assertTrue(Payload.objects.filter(vulnerability=xss_vuln).exists())
    
    def test_manipulation_tricks_created(self):
        """Test that manipulation tricks are created"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        
        # Check that manipulation tricks exist
        self.assertTrue(PayloadManipulation.objects.count() > 0)
        
        # Check for XSS manipulation tricks
        xss_vuln = VulnerabilityType.objects.get(name='XSS')
        xss_tricks = PayloadManipulation.objects.filter(vulnerability=xss_vuln)
        self.assertTrue(xss_tricks.exists())
    
    def test_nul_character_sanitization(self):
        """Test that NUL characters are properly sanitized"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        output = out.getvalue()
        
        # Check if warning was logged about NUL character removal
        # The output should mention removing NUL character
        if '\x00' in output:
            # If the literal NUL is in output, it wasn't sanitized
            self.fail("NUL character found in output - sanitization may have failed")
        
        # Verify that the "Null Byte Injection" trick was created
        xss_vuln = VulnerabilityType.objects.get(name='XSS')
        null_byte_trick = PayloadManipulation.objects.filter(
            vulnerability=xss_vuln,
            name='Null Byte Injection'
        ).first()
        
        self.assertIsNotNone(null_byte_trick, "Null Byte Injection trick should be created")
        
        # Verify that no NUL characters exist in the saved data
        self.assertNotIn('\x00', null_byte_trick.technique)
        self.assertNotIn('\x00', null_byte_trick.description)
        self.assertNotIn('\x00', null_byte_trick.example)
        
        # Verify the technique field contains the sanitized version
        # Original: '<scri\x00pt>alert(1)</script>'
        # Sanitized should be: '<script>alert(1)</script>'
        self.assertIn('<script>', null_byte_trick.technique)
    
    def test_encoding_techniques_created(self):
        """Test that encoding techniques are created"""
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        
        # Check that encoding techniques exist
        self.assertTrue(EncodingTechnique.objects.count() > 0)
        
        # Check for specific encodings
        self.assertTrue(EncodingTechnique.objects.filter(name='URL Encoding').exists())
        self.assertTrue(EncodingTechnique.objects.filter(name='Base64').exists())
    
    def test_idempotency(self):
        """Test that running the command multiple times doesn't create duplicates"""
        out = StringIO()
        
        # Run command first time
        call_command('populate_manipulator_data', stdout=out)
        first_run_output = out.getvalue()
        
        first_vuln_count = VulnerabilityType.objects.count()
        first_payload_count = Payload.objects.count()
        first_trick_count = PayloadManipulation.objects.count()
        first_encoding_count = EncodingTechnique.objects.count()
        
        # Run command second time
        out = StringIO()
        call_command('populate_manipulator_data', stdout=out)
        second_run_output = out.getvalue()
        
        # Check that counts remain the same
        self.assertEqual(VulnerabilityType.objects.count(), first_vuln_count)
        self.assertEqual(Payload.objects.count(), first_payload_count)
        self.assertEqual(PayloadManipulation.objects.count(), first_trick_count)
        self.assertEqual(EncodingTechnique.objects.count(), first_encoding_count)
        
        # Second run should say "already exists"
        self.assertIn('already exists', second_run_output)

