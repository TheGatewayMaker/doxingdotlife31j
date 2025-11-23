import { RequestHandler } from "express";
import {
  listPostFolders,
  getPostWithThumbnail,
  listPostFiles,
  getMediaUrl,
} from "../utils/r2-storage";
import { Post } from "@shared/api";

const getMimeType = (fileName: string): string => {
  const extension = fileName.toLowerCase().split(".").pop() || "";
  const mimeTypes: { [key: string]: string } = {
    // Images
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",
    svg: "image/svg+xml",

    // Videos
    mp4: "video/mp4",
    webm: "video/webm",
    mov: "video/quicktime",
    avi: "video/x-msvideo",
    mkv: "video/x-matroska",
    flv: "video/x-flv",
    m4v: "video/x-m4v",
    mpg: "video/mpeg",
    mpeg: "video/mpeg",

    // Audio
    mp3: "audio/mpeg",
    wav: "audio/wav",
    m4a: "audio/mp4",
    aac: "audio/aac",
    flac: "audio/flac",
    ogg: "audio/ogg",

    // Other
    json: "application/json",
    pdf: "application/pdf",
    txt: "text/plain",
  };

  return mimeTypes[extension] || "application/octet-stream";
};

export const handleGetPosts: RequestHandler = async (req, res) => {
  try {
    const postIds = await listPostFolders();
    const posts: Post[] = [];

    for (const postId of postIds) {
      const postData = await getPostWithThumbnail(postId);
      if (postData) {
        const mediaFiles = await listPostFiles(postId);
        const mediaFileObjects = mediaFiles
          .map((fileName) => ({
            name: fileName,
            url: getMediaUrl(`posts/${postId}/${fileName}`),
            type: getMimeType(fileName),
          }))
          .filter((f) => f.name !== "metadata.json");

        const post: Post = {
          id: postData.id,
          title: postData.title,
          description: postData.description,
          country: postData.country,
          city: postData.city,
          server: postData.server,
          thumbnail: postData.thumbnail,
          mediaFiles: mediaFileObjects,
          createdAt: postData.createdAt,
        };

        posts.push(post);
      }
    }

    posts.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );

    res.json({
      posts,
      total: posts.length,
    });
  } catch (error) {
    console.error("Error getting posts:", error);
    res.status(200).json({ posts: [], total: 0 });
  }
};
