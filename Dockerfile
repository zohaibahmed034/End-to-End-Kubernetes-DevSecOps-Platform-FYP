# Use official Ghost image as base
FROM ghost:6-alpine

# Set environment variables
ENV NODE_ENV=production \
    url=http://localhost:2368 \
    GHOST_CONTENT=/var/lib/ghost/content

# Create content directory
RUN mkdir -p $GHOST_CONTENT

# Copy local content if exists (optional)
# COPY content/ $GHOST_CONTENT/

# Expose Ghost port
EXPOSE 2368

# Set working directory
WORKDIR /var/lib/ghost

# Start Ghost
CMD ["node", "current/index.js"]
