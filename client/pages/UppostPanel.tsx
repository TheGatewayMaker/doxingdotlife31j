import { useState } from "react";
import { Upload, LogOut } from "lucide-react";
import Header from "@/components/Header";
import Footer from "@/components/Footer";

interface AuthState {
  isAuthenticated: boolean;
  username: string;
}

const VALID_USERNAME = "uploader81";
const VALID_PASSWORD = "uploader123";

export default function UppostPanel() {
  const [auth, setAuth] = useState<AuthState>({
    isAuthenticated: false,
    username: "",
  });
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [country, setCountry] = useState("");
  const [city, setCity] = useState("");
  const [server, setServer] = useState("");
  const [media, setMedia] = useState<File | null>(null);
  const [mediaPreview, setMediaPreview] = useState<string>("");
  const [uploading, setUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState("");
  const [uploadError, setUploadError] = useState("");

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");

    if (loginUsername === VALID_USERNAME && loginPassword === VALID_PASSWORD) {
      setAuth({
        isAuthenticated: true,
        username: loginUsername,
      });
      setLoginUsername("");
      setLoginPassword("");
    } else {
      setLoginError("Invalid username or password");
    }
  };

  const handleLogout = () => {
    setAuth({
      isAuthenticated: false,
      username: "",
    });
    resetForm();
  };

  const handleMediaChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setMedia(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setMediaPreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const resetForm = () => {
    setTitle("");
    setDescription("");
    setCountry("");
    setCity("");
    setServer("");
    setMedia(null);
    setMediaPreview("");
    setUploadMessage("");
    setUploadError("");
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploadError("");
    setUploadMessage("");

    if (!title || !description || !media) {
      setUploadError("Please fill in all required fields and select media");
      return;
    }

    const formData = new FormData();
    formData.append("title", title);
    formData.append("description", description);
    formData.append("country", country);
    formData.append("city", city);
    formData.append("server", server);
    formData.append("media", media);

    setUploading(true);

    try {
      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Upload failed");
      }

      const data = await response.json();
      setUploadMessage("Post uploaded successfully!");
      resetForm();
    } catch (error) {
      setUploadError("Error uploading post. Please try again.");
      console.error("Upload error:", error);
    } finally {
      setUploading(false);
    }
  };

  if (!auth.isAuthenticated) {
    return (
      <div className="min-h-screen bg-background text-foreground flex flex-col">
        <Header />
        <div className="flex-1 flex items-center justify-center px-4 py-12">
          <div className="w-full max-w-md">
            <div className="bg-card border border-border rounded-xl p-10">
              <div className="mb-2 w-10 h-10 bg-accent rounded-lg flex items-center justify-center">
                <span className="font-black text-accent-foreground">⚙️</span>
              </div>
              <h1 className="text-4xl font-black mb-2 text-foreground">Uppost Panel</h1>
              <p className="text-muted-foreground mb-8">Admin access required to manage posts</p>

              <form onSubmit={handleLogin} className="space-y-5">
                <div>
                  <label className="block text-sm font-bold mb-2 text-foreground">Username</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="w-full px-4 py-3 bg-background border border-border hover:border-accent/50 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent transition-colors"
                    placeholder="Enter username"
                    autoComplete="username"
                  />
                </div>

                <div>
                  <label className="block text-sm font-bold mb-2 text-foreground">Password</label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    className="w-full px-4 py-3 bg-background border border-border hover:border-accent/50 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent transition-colors"
                    placeholder="Enter password"
                    autoComplete="current-password"
                  />
                </div>

                {loginError && (
                  <div className="p-4 bg-destructive/10 border border-destructive rounded-lg text-destructive text-sm font-medium">
                    ⚠️ {loginError}
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full px-4 py-3 bg-accent text-accent-foreground font-bold rounded-lg hover:bg-accent/90 transition-all active:scale-95"
                >
                  Login to Dashboard
                </button>
              </form>
            </div>
          </div>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <Header />
      <main className="flex-1 w-full">
        <div className="max-w-3xl mx-auto px-4 py-12">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h1 className="text-4xl font-black mb-2">Uppost Panel</h1>
              <p className="text-muted-foreground">Logged in as: {auth.username}</p>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 bg-destructive text-destructive-foreground rounded-lg hover:bg-opacity-90 transition-all"
            >
              <LogOut className="w-5 h-5" />
              Logout
            </button>
          </div>

          <form onSubmit={handleUpload} className="bg-card border border-border rounded-lg p-8 space-y-6">
            {/* Title */}
            <div>
              <label className="block text-sm font-semibold mb-2">
                Title <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
                placeholder="Post title"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-semibold mb-2">
                Description <span className="text-destructive">*</span>
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent resize-none"
                rows={4}
                placeholder="Post description"
              />
            </div>

            {/* Country */}
            <div>
              <label className="block text-sm font-semibold mb-2">Country</label>
              <input
                type="text"
                value={country}
                onChange={(e) => setCountry(e.target.value)}
                className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
                placeholder="Country (optional)"
              />
            </div>

            {/* City */}
            <div>
              <label className="block text-sm font-semibold mb-2">City</label>
              <input
                type="text"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
                placeholder="City (optional)"
              />
            </div>

            {/* Server */}
            <div>
              <label className="block text-sm font-semibold mb-2">Server Name</label>
              <input
                type="text"
                value={server}
                onChange={(e) => setServer(e.target.value)}
                className="w-full px-4 py-2 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-accent"
                placeholder="Server name (optional)"
              />
              <p className="text-xs text-muted-foreground mt-1">
                This server will be added to the servers list
              </p>
            </div>

            {/* Media Upload */}
            <div>
              <label className="block text-sm font-semibold mb-2">
                Media <span className="text-destructive">*</span>
              </label>
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-accent transition-colors">
                <input
                  type="file"
                  onChange={handleMediaChange}
                  accept="image/*,video/*"
                  className="hidden"
                  id="media-upload"
                />
                <label htmlFor="media-upload" className="cursor-pointer block">
                  {media ? (
                    <div className="space-y-2">
                      <p className="text-sm font-medium text-accent">{media.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {(media.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <Upload className="w-8 h-8 mx-auto text-muted-foreground" />
                      <p className="text-sm font-medium">Click to upload media</p>
                      <p className="text-xs text-muted-foreground">
                        Images and videos supported
                      </p>
                    </div>
                  )}
                </label>
              </div>

              {mediaPreview && (
                <div className="mt-4 relative">
                  {media?.type.startsWith("image/") ? (
                    <img
                      src={mediaPreview}
                      alt="Preview"
                      className="max-h-48 rounded-lg mx-auto"
                    />
                  ) : (
                    <video
                      src={mediaPreview}
                      controls
                      className="max-h-48 rounded-lg mx-auto"
                    />
                  )}
                </div>
              )}
            </div>

            {uploadMessage && (
              <div className="p-4 bg-green-900 bg-opacity-20 border border-green-600 rounded text-green-400 text-sm">
                {uploadMessage}
              </div>
            )}

            {uploadError && (
              <div className="p-4 bg-destructive bg-opacity-10 border border-destructive rounded text-destructive text-sm">
                {uploadError}
              </div>
            )}

            <button
              type="submit"
              disabled={uploading}
              className="w-full px-4 py-3 bg-accent text-accent-foreground font-semibold rounded-lg hover:bg-opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {uploading ? "Uploading..." : "Upload Post"}
            </button>
          </form>
        </div>
      </main>
      <Footer />
    </div>
  );
}
