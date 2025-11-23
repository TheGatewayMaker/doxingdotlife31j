# Deployment Checklist for Doxing Dot Life

This checklist guides you through deploying the enhanced application to Netlify with R2 storage configured.

## Step 1: Prepare Your R2 Account

- [ ] Have your Cloudflare account ready
- [ ] Note your **Cloudflare Account ID** from the dashboard
- [ ] Create an R2 bucket (or use existing):
  - [ ] Bucket name (e.g., `doxing-dot-life`)
  - [ ] Note the bucket name
- [ ] Create R2 API Token with these permissions:
  - [ ] List buckets
  - [ ] Create/Delete bucket
  - [ ] List objects
  - [ ] Read objects
  - [ ] Write objects
  - [ ] Delete objects
- [ ] Copy and save:
  - [ ] Access Key ID
  - [ ] Secret Access Key

## Step 2: Set Up Netlify Environment Variables

### Option A: Using Netlify UI
1. Log in to [Netlify Dashboard](https://app.netlify.com)
2. Select your "Doxing Dot Life" site
3. Go to **Site settings** → **Build & deploy** → **Environment**
4. Click **Edit variables**
5. Add these environment variables:

   | Variable Name | Value |
   |---|---|
   | `R2_ACCOUNT_ID` | Your Cloudflare Account ID |
   | `R2_ACCESS_KEY_ID` | Your R2 API Access Key ID |
   | `R2_SECRET_ACCESS_KEY` | Your R2 API Secret Access Key |
   | `R2_BUCKET_NAME` | Your bucket name (e.g., `doxing-dot-life`) |
   | `R2_PUBLIC_URL` | (Optional) Your public URL if configured |

6. Click **Save**

### Option B: Using Netlify CLI
```bash
netlify env:set R2_ACCOUNT_ID "your_account_id"
netlify env:set R2_ACCESS_KEY_ID "your_access_key_id"
netlify env:set R2_SECRET_ACCESS_KEY "your_secret_access_key"
netlify env:set R2_BUCKET_NAME "your_bucket_name"
netlify env:set R2_PUBLIC_URL "your_public_url" # Optional
```

## Step 3: Deploy to Netlify

1. Commit and push your code to your Git repository
2. Trigger a new deploy:
   - [ ] Using Netlify UI: Push the deploy button in your site settings
   - [ ] Using Git: Push to your connected branch
   - [ ] Using CLI: Run `netlify deploy --prod`

## Step 4: Verify Deployment

- [ ] Visit your deployed site (check Netlify domain)
- [ ] Create a test post with media files
- [ ] Verify files upload to R2:
  - Check [R2 Dashboard](https://dash.cloudflare.com) → R2 section
  - You should see a `posts/` folder with your uploads
- [ ] Verify files display on the site:
  - [ ] Images show in lightbox when clicked
  - [ ] Videos play with controls and fullscreen button
  - [ ] Media thumbnails appear in the grid
  - [ ] Download buttons work
  - [ ] Navigation between media works

## Step 5: Test Media Features

### Image Lightbox
- [ ] Click an image in the post detail page
- [ ] Image opens in fullscreen modal
- [ ] Can navigate with arrow buttons
- [ ] Can download with download button
- [ ] Close button (X) works
- [ ] Clicking outside closes the modal

### Video Fullscreen
- [ ] Click fullscreen icon on video player
- [ ] Video enters fullscreen mode
- [ ] All video controls work (play, pause, volume, progress)
- [ ] Close button (X) closes fullscreen
- [ ] Video thumbnail appears in grid

### Media Gallery
- [ ] All media types show appropriate icons (images, videos, audio)
- [ ] Can click any thumbnail to view in preview
- [ ] Navigation arrows work smoothly
- [ ] Media counter shows current position
- [ ] File information displays correctly

## Troubleshooting

### Issue: "No Posts Found" after deployment
- [ ] Check environment variables are set in Netlify (not in .env)
- [ ] Redeploy after setting variables
- [ ] Check that R2_BUCKET_NAME matches the actual bucket name

### Issue: Media uploads but doesn't display
- [ ] Verify R2_PUBLIC_URL is correct (if set)
- [ ] Check R2 bucket has public read access (if needed)
- [ ] Verify the media URL in browser DevTools
- [ ] Check R2 bucket in Cloudflare dashboard for uploaded files

### Issue: Video doesn't play
- [ ] Check video format is supported (MP4, WebM, MOV, AVI, MKV, etc.)
- [ ] Verify video file uploaded correctly to R2
- [ ] Test with a smaller/different video file
- [ ] Check browser console for CORS errors

### Issue: Upload fails with permission error
- [ ] Verify R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY are correct
- [ ] Check API token has Write and Delete permissions
- [ ] Verify token hasn't expired
- [ ] Check R2 bucket exists

## Features Overview

### New Media Viewer Component
- ✅ Image lightbox with fullscreen support
- ✅ Video player with fullscreen capability
- ✅ Audio player with controls
- ✅ Media gallery with thumbnails
- ✅ Navigation between media files
- ✅ Download functionality
- ✅ Support for all common media types

### Supported Media Types
- **Images**: JPG, PNG, WebP, GIF, SVG, BMP, TIFF, ICO
- **Videos**: MP4, WebM, MOV, AVI, MKV, FLV, M4V, MPEG, WMV, OGV
- **Audio**: MP3, WAV, M4A, AAC, FLAC, OGG, OPUS, WMA, AIFF

## Performance Optimizations

- [ ] R2 requests are optimized for speed
- [ ] Media files use appropriate MIME types
- [ ] Thumbnails are lazy-loaded
- [ ] Videos use preload="metadata" for faster initial load

## Security Notes

- [ ] Never commit `.env` files with secrets
- [ ] Use Netlify environment variables for sensitive data
- [ ] R2 API tokens should have minimal required permissions
- [ ] Consider setting token expiration dates
- [ ] Regularly rotate API tokens

## Documentation

For more detailed information, see:
- [NETLIFY_SETUP.md](./NETLIFY_SETUP.md) - Complete R2 setup guide
- [.env.example](./.env.example) - Environment variable template
- [AGENTS.md](./AGENTS.md) - Project architecture overview

---

**Last Updated**: 2024
**Status**: Ready for production deployment
