#!/bin/bash
# Script to commit and push Odoo addon to GitHub

echo "=========================================="
echo "ITX Security Shield - GitHub Push Script"
echo "=========================================="
echo ""

# Set git user (แก้ไขเป็นของคุณ!)
echo "1. Setting git user..."
git config user.name "Chainaris Padungkul"  # ← แก้ตรงนี้!
git config user.email "chainarisp@gmail.com"  # ← แก้ตรงนี้!

# Commit
echo ""
echo "2. Committing changes..."
git commit -m "feat: Complete license management system with hardware binding

Implements comprehensive license validation and management for Odoo addons.

Features:
- AES-256-GCM encrypted license files
- Hardware fingerprinting (6 values)
- Multi-instance license support
- License expiry and grace period management

Components:
- License Format & Encryption (tools/)
- Odoo Integration (models/, views/)
- C Library Integration (lib/)

Usage:
  python3 tools/promote_to_prod.py --customer 'Company' --expiry '2025-12-31' --bind-hardware
  python3 tools/view_license.py production.lic

🤖 Generated with Claude Code (https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# Add remote (แก้เป็น GitHub URL ของคุณ!)
echo ""
echo "3. Adding remote..."
git remote add origin https://github.com/chainarp/itx_security_shield.git  # ← แก้ตรงนี้!

# Push
echo ""
echo "4. Pushing to GitHub..."
git push -u origin master

echo ""
echo "=========================================="
echo "✅ Done!"
echo "=========================================="
