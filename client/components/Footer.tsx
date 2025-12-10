import {
  HomeIcon,
  LinkIcon,
  SearchAltIcon,
  MessageIcon,
  FileTextIcon,
  ScaleIcon,
  AlertIcon,
  ShoppingCartIcon,
  CreditCardIcon,
  PhoneIcon,
  MailIcon,
} from "@/components/Icons";

export default function Footer() {
  return (
    <footer className="w-full bg-[#000000] border-t border-[#666666] mt-12 sm:mt-16 lg:mt-20 shadow-lg animate-slideInUp">
      <div className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 lg:px-8 py-8 sm:py-12 md:py-16">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 sm:gap-8 md:gap-10 lg:gap-12 mb-6 sm:mb-8">
          <div
            className="animate-slideInLeftFade"
            style={{ animationDelay: "0.1s" }}
          >
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 sm:w-12 h-10 sm:h-12 rounded-full overflow-hidden flex-shrink-0 shadow-lg">
                <img
                  src="https://i.ibb.co/PzNWvp7N/doxinglifelogo.png"
                  alt="Doxing Dot Life Logo"
                  className="w-full h-full object-cover"
                  loading="lazy"
                />
              </div>
              <div className="min-w-0">
                <h3 className="font-black text-white text-base sm:text-lg line-clamp-1">
                  Doxing Dot Life
                </h3>
                <p className="text-xs text-gray-500">Doxing Database</p>
              </div>
            </div>
            <p className="text-xs sm:text-sm text-[#979797] leading-relaxed">
              The largest database of exposed and doxed individuals. Find and
              share information about anyone.
            </p>
          </div>
          <div className="animate-slideInUp" style={{ animationDelay: "0.2s" }}>
            <h4 className="font-bold text-white mb-3 sm:mb-4 flex items-center gap-2 text-xs sm:text-sm uppercase tracking-wider">
              <LinkIcon className="w-4 h-4 text-[#979797] flex-shrink-0" />
              <span>Navigation</span>
            </h4>
            <ul className="space-y-2 sm:space-y-2.5 text-xs sm:text-sm text-[#979797]">
              <li>
                <a
                  href="/"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <HomeIcon className="w-4 h-4 flex-shrink-0" />
                  <span>Home</span>
                </a>
              </li>
              <li>
                <a
                  href="/all-posts"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <SearchAltIcon className="w-4 h-4 flex-shrink-0" />
                  <span className="line-clamp-1">Browse Database</span>
                </a>
              </li>
              <li>
                <a
                  href="/dox-anyone"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <MessageIcon className="w-4 h-4 flex-shrink-0" />
                  <span>Search Tool</span>
                </a>
              </li>
            </ul>
          </div>
          <div className="animate-slideInUp" style={{ animationDelay: "0.3s" }}>
            <h4 className="font-bold text-white mb-3 sm:mb-4 flex items-center gap-2 text-xs sm:text-sm uppercase tracking-wider">
              <FileTextIcon className="w-4 h-4 text-[#979797] flex-shrink-0" />
              <span>Legal</span>
            </h4>
            <ul className="space-y-2 sm:space-y-2.5 text-xs sm:text-sm text-[#979797]">
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <FileTextIcon className="w-4 h-4 flex-shrink-0" />
                  <span className="line-clamp-1">Privacy Policy</span>
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <ScaleIcon className="w-4 h-4 flex-shrink-0" />
                  <span className="line-clamp-1">Terms of Service</span>
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <AlertIcon className="w-4 h-4 flex-shrink-0" />
                  <span>Disclaimer</span>
                </a>
              </li>
            </ul>
          </div>
          <div className="animate-slideInUp" style={{ animationDelay: "0.4s" }}>
            <h4 className="font-bold text-white mb-3 sm:mb-4 flex items-center gap-2 text-xs sm:text-sm uppercase tracking-wider">
              <MessageIcon className="w-4 h-4 text-[#979797] flex-shrink-0" />
              <span>Support</span>
            </h4>
            <ul className="space-y-2 sm:space-y-2.5 text-xs sm:text-sm text-[#979797]">
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <FileTextIcon className="w-4 h-4 flex-shrink-0" />
                  <span className="line-clamp-1">API Documentation</span>
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <MessageIcon className="w-4 h-4 flex-shrink-0" />
                  <span>FAQ & Help</span>
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="hover:text-[#0088CC] transition-colors duration-200 flex items-center gap-2 hover:translate-x-1 py-1"
                >
                  <AlertIcon className="w-4 h-4 flex-shrink-0" />
                  <span className="line-clamp-1">Report Data Issue</span>
                </a>
              </li>
            </ul>
          </div>
        </div>
        <div className="border-t border-[#666666] pt-6 sm:pt-8 md:pt-10">
          <div className="text-center text-xs sm:text-sm text-[#666666]">
            <p>&copy; 2024 - 2027 Doxing Dot Life. All rights reserved.</p>
            <p className="mt-2 text-[#666666]">
              Find, Dox, Expose - The Database
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}
