import { Link, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { Menu, X, LogOut } from "lucide-react";
import {
  HomeIcon,
  UploadIcon,
  SettingsIcon,
  SearchAltIcon,
} from "@/components/Icons";
import { useAuthContext } from "@/contexts/AuthContext";

export default function Header() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { isAuthenticated, logout } = useAuthContext();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (isSidebarOpen) {
      document.body.classList.add("overflow-hidden");
    } else {
      document.body.classList.remove("overflow-hidden");
    }

    return () => {
      document.body.classList.remove("overflow-hidden");
    };
  }, [isSidebarOpen]);

  useEffect(() => {
    const handleEscapeKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isSidebarOpen) {
        setIsSidebarOpen(false);
      }
    };

    document.addEventListener("keydown", handleEscapeKey);
    return () => document.removeEventListener("keydown", handleEscapeKey);
  }, [isSidebarOpen]);

  const closeSidebar = () => {
    setIsSidebarOpen(false);
  };

  const handleLogout = async () => {
    await logout();
    closeSidebar();
    navigate("/");
  };

  return (
    <header className="w-full bg-[#000000] backdrop-blur-md border-b border-[#666666] shadow-lg animate-slideInDown sticky top-0 z-50 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
        <Link
          to="/"
          className="flex items-center gap-2 sm:gap-3 hover:opacity-90 transition-opacity flex-shrink-0"
        >
          <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-full overflow-hidden shadow-md flex-shrink-0">
            <img
              src="https://i.ibb.co/PzNWvp7N/doxinglifelogo.png"
              alt="Doxing Dot Life Logo"
              className="w-full h-full object-cover"
            />
          </div>
          <span className="font-black text-base sm:text-lg text-white hidden xs:inline line-clamp-1">
            Doxing Dot Life
          </span>
          <span className="font-black text-base sm:text-lg text-white xs:hidden">
            DDL
          </span>
        </Link>

        {/* Desktop Navigation */}
        <nav
          className="hidden lg:flex items-center gap-6 xl:gap-8 animate-fadeIn"
          style={{ animationDelay: "0.2s" }}
        >
          <Link
            to="/"
            className="flex items-center gap-2 text-sm font-semibold text-[#979797] hover:text-white transition-colors duration-200 hover:scale-105"
          >
            <HomeIcon className="w-4 h-4 sm:w-5 sm:h-5" />
            <span className="hidden xl:inline">Home</span>
          </Link>
          <Link
            to="/all-posts"
            className="text-sm font-semibold text-[#979797] hover:text-white transition-colors duration-200"
          >
            Posts
          </Link>
          <Link
            to="/dox-anyone"
            className="flex items-center gap-2 px-5 py-2 bg-[#0088CC] text-white font-semibold rounded-lg hover:bg-[#0077BB] transition-all duration-200 shadow-md hover:shadow-lg hover:shadow-[#0088CC]/40 active:scale-95"
          >
            <SearchAltIcon className="w-4 h-4" />
            <span>Dox Now</span>
          </Link>
          {isAuthenticated && (
            <>
              {location.pathname !== "/uppostpanel" && (
                <Link
                  to="/uppostpanel"
                  className="flex items-center gap-2 px-5 py-2 bg-purple-600 text-white font-semibold rounded-lg hover:bg-purple-700 transition-all duration-200 shadow-md hover:shadow-lg hover:shadow-purple-600/40 active:scale-95"
                >
                  <UploadIcon className="w-4 h-4" />
                  <span className="hidden xl:inline">Upload</span>
                </Link>
              )}
              {location.pathname !== "/admin-panel" && (
                <Link
                  to="/admin-panel"
                  className="flex items-center gap-2 px-5 py-2 bg-amber-600 text-white font-semibold rounded-lg hover:bg-amber-700 transition-all duration-200 shadow-md hover:shadow-lg hover:shadow-amber-600/40 active:scale-95"
                >
                  <SettingsIcon className="w-4 h-4" />
                  <span className="hidden xl:inline">Admin</span>
                </Link>
              )}
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 px-5 py-2 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 transition-all duration-200 shadow-md hover:shadow-lg hover:shadow-red-600/40 active:scale-95"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden xl:inline">Logout</span>
              </button>
            </>
          )}
        </nav>

        {/* Mobile Menu Button */}
        <button
          className="lg:hidden p-2 hover:bg-[#666666]/40 active:bg-[#666666]/60 rounded-lg transition-all duration-200 relative touch-manipulation focus:outline-none focus:ring-2 focus:ring-[#0088CC] focus:ring-offset-2 focus:ring-offset-[#000000]"
          onClick={() => setIsSidebarOpen(!isSidebarOpen)}
          aria-label={
            isSidebarOpen ? "Close navigation menu" : "Toggle navigation menu"
          }
          aria-expanded={isSidebarOpen}
          aria-controls="mobile-menu"
        >
          {isSidebarOpen ? (
            <X className="w-6 h-6 text-white" />
          ) : (
            <Menu className="w-6 h-6 text-white" />
          )}
        </button>

        {/* Mobile Sidebar Navigation */}
        {isSidebarOpen && (
          <>
            {/* Overlay */}
            <div
              className="fixed inset-0 bg-black/60 lg:hidden animate-fadeIn"
              onClick={closeSidebar}
              role="presentation"
              aria-hidden="true"
              style={{ zIndex: 999 }}
            />

            {/* Sidebar */}
            <div
              id="mobile-menu"
              className="fixed top-0 left-0 right-0 bottom-0 w-full bg-[#000000] lg:hidden shadow-2xl flex flex-col overflow-hidden"
              style={{
                zIndex: 1000,
                animation: "slideInDown 0.3s ease-out forwards",
              }}
              role="navigation"
              aria-label="Mobile navigation"
            >
              {/* Header padding for mobile menu */}
              <div className="h-16 sm:h-20 border-b border-[#666666] flex items-center px-4 sm:px-6 flex-shrink-0">
                <h2 className="text-lg sm:text-xl font-bold text-white">
                  Navigation
                </h2>
              </div>

              {/* Scrollable menu content */}
              <nav className="flex-1 overflow-y-auto px-2 sm:px-4 py-4 sm:py-6 space-y-2">
                <Link
                  to="/"
                  onClick={closeSidebar}
                  className="flex items-center gap-3 w-full px-3 sm:px-4 py-3 sm:py-4 text-[#979797] font-semibold hover:bg-[#666666]/40 hover:text-white rounded-lg transition-all duration-200 active:bg-[#666666]/60 text-base sm:text-lg touch-target"
                >
                  <HomeIcon className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" />
                  <span>Home</span>
                </Link>
                <Link
                  to="/all-posts"
                  onClick={closeSidebar}
                  className="flex items-center gap-3 w-full px-3 sm:px-4 py-3 sm:py-4 text-[#979797] font-semibold hover:bg-[#666666]/40 hover:text-white rounded-lg transition-all duration-200 active:bg-[#666666]/60 text-base sm:text-lg touch-target"
                >
                  <span className="text-lg sm:text-2xl">📋</span>
                  <span>All Posts</span>
                </Link>
                <Link
                  to="/dox-anyone"
                  onClick={closeSidebar}
                  className="flex items-center gap-3 w-full px-3 sm:px-4 py-3 sm:py-4 text-white font-semibold hover:bg-[#0077BB] rounded-lg transition-all duration-200 bg-[#0088CC] active:bg-[#0066AA] text-base sm:text-lg touch-target"
                >
                  <SearchAltIcon className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" />
                  <span>Dox Now</span>
                </Link>
                {isAuthenticated && (
                  <>
                    <div className="my-2 sm:my-4 border-t border-[#666666]" />
                    {location.pathname !== "/uppostpanel" && (
                      <Link
                        to="/uppostpanel"
                        onClick={closeSidebar}
                        className="flex items-center gap-3 w-full px-3 sm:px-4 py-3 sm:py-4 bg-purple-600 text-white font-semibold hover:bg-purple-700 rounded-lg transition-all duration-200 active:bg-purple-800 text-base sm:text-lg touch-target"
                      >
                        <UploadIcon className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" />
                        <span>Upload Post</span>
                      </Link>
                    )}
                    {location.pathname !== "/admin-panel" && (
                      <Link
                        to="/admin-panel"
                        onClick={closeSidebar}
                        className="flex items-center gap-3 w-full px-3 sm:px-4 py-3 sm:py-4 bg-amber-600 text-white font-semibold hover:bg-amber-700 rounded-lg transition-all duration-200 active:bg-amber-800 text-base sm:text-lg touch-target"
                      >
                        <SettingsIcon className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" />
                        <span>Admin Panel</span>
                      </Link>
                    )}
                  </>
                )}
              </nav>

              {/* Footer section with logout button */}
              {isAuthenticated && (
                <div className="p-3 sm:p-4 border-t border-[#666666] bg-[#0a0a0a] flex-shrink-0">
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center justify-center gap-2 px-3 sm:px-4 py-3 sm:py-4 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 transition-all duration-200 shadow-md hover:shadow-lg hover:shadow-red-600/40 active:bg-red-800 text-base sm:text-lg touch-target"
                  >
                    <LogOut className="w-5 h-5" />
                    <span>Logout</span>
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </header>
  );
}
