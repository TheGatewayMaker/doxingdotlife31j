import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import SearchBar from "@/components/SearchBar";
import { Post, PostsResponse } from "@shared/api";
import { GlobeIcon, MapPinIcon, ServerIcon } from "@/components/Icons";
import { Flame } from "lucide-react";

export default function Index() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCountry, setSelectedCountry] = useState("");
  const [selectedServer, setSelectedServer] = useState("");
  const [servers, setServers] = useState<string[]>([]);
  const [posts, setPosts] = useState<Post[]>([]);
  const [filteredPosts, setFilteredPosts] = useState<Post[]>([]);
  const [displayedPosts, setDisplayedPosts] = useState<Post[]>([]);
  const [postsPerPage] = useState(12);
  const [currentPage, setCurrentPage] = useState(1);
  const [isLoadingPosts, setIsLoadingPosts] = useState(true);
  const [hasSearchFilters, setHasSearchFilters] = useState(false);

  useEffect(() => {
    const loadPosts = async () => {
      setIsLoadingPosts(true);
      try {
        const response = await fetch("/api/posts");
        const data: PostsResponse = await response.json();
        setPosts(Array.isArray(data.posts) ? data.posts : []);
      } catch (error) {
        console.error("Error loading posts:", error);
        setPosts([]);
      } finally {
        setIsLoadingPosts(false);
      }
    };

    const loadServers = async () => {
      try {
        const response = await fetch("/api/servers");
        const data = await response.json();
        setServers(Array.isArray(data.servers) ? data.servers : []);
      } catch (error) {
        console.error("Error loading servers:", error);
        setServers([]);
      }
    };

    loadPosts();
    loadServers();
  }, []);

  useEffect(() => {
    let filtered = posts;
    const hasFilters = !!searchQuery || !!selectedCountry || !!selectedServer;
    setHasSearchFilters(hasFilters);

    if (searchQuery) {
      filtered = filtered.filter(
        (post) =>
          post.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          post.description.toLowerCase().includes(searchQuery.toLowerCase()),
      );
    }

    if (selectedCountry) {
      filtered = filtered.filter((post) => post.country === selectedCountry);
    }

    if (selectedServer) {
      filtered = filtered.filter((post) => post.server === selectedServer);
    }

    filtered.sort((a, b) => {
      if (a.isTrend && b.isTrend) {
        return (
          (a.trendRank ?? Number.MAX_VALUE) - (b.trendRank ?? Number.MAX_VALUE)
        );
      }
      if (a.isTrend) return -1;
      if (b.isTrend) return 1;
      return 0;
    });

    setFilteredPosts(filtered);
    setCurrentPage(1);
  }, [posts, searchQuery, selectedCountry, selectedServer]);

  useEffect(() => {
    const start = (currentPage - 1) * postsPerPage;
    const end = start + postsPerPage;
    setDisplayedPosts(filteredPosts.slice(start, end));
  }, [filteredPosts, currentPage, postsPerPage]);

  const totalPages = Math.ceil(filteredPosts.length / postsPerPage);

  return (
    <div className="min-h-screen bg-[#000000] text-white flex flex-col animate-fadeIn">
      <Header />

      <main className="flex-1 w-full">
        {/* Hero Section */}
        <div className="bg-[#000000] py-6 sm:py-10 md:py-16 lg:py-20 border-b border-[#666666]">
          <div className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 lg:px-8">
            <div
              className="animate-slideInLeftFade"
              style={{ animationDelay: "0.1s" }}
            >
              <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-black mb-3 sm:mb-4 md:mb-5 text-white tracking-tighter leading-tight">
                Doxing Dot Life
              </h1>
              <p className="text-sm sm:text-base md:text-lg lg:text-xl font-medium text-[#979797] mb-5 sm:mb-6 md:mb-8 max-w-3xl leading-relaxed">
                The largest database of exposed individuals. Search, dox, and
                expose information on anyone in our comprehensive directory.
              </p>
            </div>

            {/* Search Bar Component */}
            <SearchBar
              searchQuery={searchQuery}
              selectedCountry={selectedCountry}
              selectedServer={selectedServer}
              servers={servers}
              onSearchChange={setSearchQuery}
              onCountryChange={setSelectedCountry}
              onServerChange={setSelectedServer}
            />
          </div>
        </div>

        {/* Posts Section */}
        <div className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 lg:px-8 py-8 sm:py-10 md:py-12 lg:py-16">
          <div className="mb-8 sm:mb-10 md:mb-12 animate-slideInUp">
            {isLoadingPosts ? (
              <>
                <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-black mb-2 sm:mb-3 flex items-center gap-2 sm:gap-3 text-white">
                  <span className="inline-block animate-spin">
                    <div className="w-6 h-6 sm:w-8 sm:h-8 border-3 border-[#666666] border-t-[#0088CC] rounded-full"></div>
                  </span>
                  <span>Loading Posts</span>
                </h2>
                <p className="text-[#979797] text-xs sm:text-sm md:text-base">
                  Fetching the latest posts for you...
                </p>
              </>
            ) : filteredPosts.length === 0 ? (
              <>
                <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-black mb-2 sm:mb-3 text-white">
                  No Posts Found
                </h2>
                <p className="text-[#979797] text-xs sm:text-sm md:text-base">
                  {hasSearchFilters
                    ? "Try adjusting your search filters"
                    : "No posts available at the moment"}
                </p>
              </>
            ) : (
              <>
                <div className="flex items-center gap-1.5 sm:gap-2 md:gap-3 mb-1.5 sm:mb-2 md:mb-3">
                  <Flame className="w-5 h-5 sm:w-6 sm:h-6 md:w-8 md:h-8 text-orange-500" />
                  <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-black text-white">
                    Trending
                  </h2>
                </div>
                <p className="text-[#979797] text-xs sm:text-sm md:text-base">
                  Showing {displayedPosts.length} of {filteredPosts.length}{" "}
                  result{filteredPosts.length !== 1 ? "s" : ""}
                </p>
              </>
            )}
          </div>

          {displayedPosts.length > 0 ? (
            <>
              <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 sm:gap-4 md:gap-5 lg:gap-6 mb-8 sm:mb-10 md:mb-12">
                {displayedPosts.map((post, idx) => (
                  <div
                    key={post.id}
                    onClick={() => navigate(`/post/${post.id}`)}
                    className={cn(
                      "group rounded-lg sm:rounded-xl overflow-hidden transition-all duration-300 cursor-pointer hover:-translate-y-2 animate-scaleUpFadeIn border hover:shadow-2xl flex flex-col h-full active:scale-95 sm:active:scale-100",
                      post.isTrend
                        ? "bg-gradient-to-br from-[#4a3a1a] via-[#3a2a1a] to-[#2a1a0a] border-[#9d7e1f] hover:border-[#ffd700] hover:shadow-[#ffd700]/20"
                        : "bg-[#1a1a1a] border-[#666666] hover:border-[#0088CC] hover:shadow-[#0088CC]/20",
                    )}
                    style={{ animationDelay: `${idx * 0.08}s` }}
                    role="link"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        navigate(`/post/${post.id}`);
                      }
                    }}
                  >
                    {post.thumbnail && (
                      <div className="w-full aspect-square bg-[#1a1a1a] overflow-hidden flex items-center justify-center relative flex-shrink-0">
                        <img
                          src={post.thumbnail}
                          alt={post.title}
                          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                          onError={(e) => {
                            const img = e.target as HTMLImageElement;
                            img.style.display = "none";
                            const parent = img.parentElement;
                            if (
                              parent &&
                              !parent.querySelector("[data-error-shown]")
                            ) {
                              const errorDiv = document.createElement("div");
                              errorDiv.setAttribute("data-error-shown", "true");
                              errorDiv.className =
                                "absolute inset-0 bg-[#0a0a0a] text-center text-[#666666] flex flex-col items-center justify-center gap-1 sm:gap-2 w-full h-full";
                              errorDiv.innerHTML =
                                '<div class="text-2xl sm:text-3xl">🖼️</div><div class="text-xs">Image unavailable</div>';
                              parent.appendChild(errorDiv);
                            }
                          }}
                          crossOrigin="anonymous"
                          loading="lazy"
                          decoding="async"
                        />
                      </div>
                    )}
                    <div className="p-2 sm:p-3 flex-1 flex flex-col">
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <h3 className="font-bold text-xs line-clamp-1 flex-1 text-white group-hover:text-[#0088CC] transition-colors">
                          {post.title}
                        </h3>
                        {post.nsfw && (
                          <span className="inline-flex items-center gap-0.5 bg-red-600 text-white px-1.5 py-0.5 rounded text-xs font-bold flex-shrink-0 whitespace-nowrap">
                            NSFW
                          </span>
                        )}
                      </div>
                      <p className="text-xs line-clamp-1 mb-2 text-[#979797] flex-1">
                        {post.description}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {post.country && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-xs font-medium bg-[#666666] text-white border border-[#979797] flex-shrink-0">
                            <GlobeIcon className="w-3 h-3" />
                            <span className="hidden sm:inline">
                              {post.country}
                            </span>
                            <span className="sm:hidden">
                              {post.country.substring(0, 3)}
                            </span>
                          </span>
                        )}
                        {post.city && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-xs font-medium bg-[#666666] text-white border border-[#979797] flex-shrink-0">
                            <MapPinIcon className="w-3 h-3" />
                            <span className="hidden sm:inline">
                              {post.city}
                            </span>
                            <span className="sm:hidden">
                              {post.city.substring(0, 3)}
                            </span>
                          </span>
                        )}
                        {post.server && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-xs font-medium bg-[#666666] text-white border border-[#979797] flex-shrink-0">
                            <ServerIcon className="w-3 h-3" />
                            <span className="hidden sm:inline">
                              {post.server}
                            </span>
                            <span className="sm:hidden">
                              {post.server.substring(0, 3)}
                            </span>
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div
                  className="flex flex-wrap justify-center items-center gap-1.5 sm:gap-2 md:gap-3 animate-slideInUp px-2 py-4"
                  style={{ animationDelay: "0.4s" }}
                >
                  <button
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                    className="px-2.5 sm:px-3 md:px-4 py-2 bg-[#0088CC] text-white font-semibold rounded text-xs sm:text-sm hover:bg-[#0077BB] disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md hover:shadow-lg hover:shadow-[#0088CC]/40 active:scale-95 touch-target min-h-[44px]"
                  >
                    ← Prev
                  </button>
                  <div className="flex items-center gap-0.5 sm:gap-1 flex-wrap justify-center">
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(
                      (page) => (
                        <button
                          key={page}
                          onClick={() => setCurrentPage(page)}
                          className={cn(
                            "w-8 h-8 sm:w-9 md:w-10 rounded font-semibold transition-all text-xs shadow-sm hover:shadow-md touch-target",
                            currentPage === page
                              ? "bg-[#0088CC] text-white"
                              : "bg-[#1a1a1a] border border-[#666666] hover:border-[#0088CC] hover:bg-[#0088CC]/10 text-[#979797]",
                          )}
                        >
                          {page}
                        </button>
                      ),
                    )}
                  </div>
                  <button
                    onClick={() =>
                      setCurrentPage(Math.min(totalPages, currentPage + 1))
                    }
                    disabled={currentPage === totalPages}
                    className="px-2.5 sm:px-3 md:px-4 py-2 bg-[#0088CC] text-white font-semibold rounded text-xs sm:text-sm hover:bg-[#0077BB] disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md hover:shadow-lg hover:shadow-[#0088CC]/40 active:scale-95 touch-target min-h-[44px]"
                  >
                    Next →
                  </button>
                </div>
              )}
            </>
          ) : (
            <div
              className="text-center py-16 sm:py-20 animate-popIn"
              style={{ animationDelay: "0.2s" }}
            >
              <div
                className="text-5xl sm:text-6xl mb-4 animate-slideInDown"
                style={{ animationDelay: "0.3s" }}
              >
                🔍
              </div>
              <p className="text-[#979797] text-sm sm:text-base max-w-lg mx-auto">
                No posts match your current search filters. Try adjusting your
                search terms or filters.
              </p>
            </div>
          )}
        </div>
      </main>

      <Footer />
    </div>
  );
}
