import Header from "@/components/Header";
import Footer from "@/components/Footer";
import { ArrowRight } from "lucide-react";

export default function DoxAnyone() {
  const handleDoxNow = () => {
    window.open("https://discord.gg/95eC83gtFN", "_blank");
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white flex flex-col animate-fadeIn">
      <Header />
      <main className="flex-1 w-full">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 md:py-8">
          {/* Header Section */}
          <div
            className="text-center mb-6 sm:mb-8 animate-slideInDown"
            style={{ animationDelay: "0.1s" }}
          >
            <h1 className="text-2xl sm:text-3xl md:text-4xl font-black mb-2 text-[#0088CC]">
              Dox Anyone
            </h1>
            <p className="text-sm text-[#979797] max-w-2xl mx-auto font-semibold">
              Expose individuals on our platform
            </p>
          </div>

          {/* Pricing Section */}
          <div
            className="bg-[#1a1a1a] border-2 border-[#666666] rounded-lg p-4 sm:p-6 mb-6 sm:mb-8 animate-scaleUpFadeIn"
            style={{ animationDelay: "0.2s" }}
          >
            <h2 className="text-lg sm:text-xl font-black mb-4 text-white">
              Pricing
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
              <div className="bg-[#0a0a0a] rounded-lg p-4 border border-[#00A8E8] hover:border-[#00C4FF] hover:shadow-lg hover:shadow-[#00A8E8]/30 transition-all duration-300">
                <p className="text-xs font-black text-[#00A8E8] mb-1 uppercase tracking-wider">
                  United States
                </p>
                <p className="text-2xl font-black text-[#00A8E8]">$ 1.10</p>
                <p className="text-xs text-[#00A8E8] font-bold">USD</p>
              </div>
              <div className="bg-[#0a0a0a] rounded-lg p-4 border border-[#FF9500] hover:border-[#FFB84D] hover:shadow-lg hover:shadow-[#FF9500]/30 transition-all duration-300">
                <p className="text-xs font-black text-[#FFB84D] mb-1 uppercase tracking-wider">
                  India
                </p>
                <p className="text-2xl font-black text-[#FFB84D]">₹ 99</p>
                <p className="text-xs text-[#FFB84D] font-bold">INR</p>
              </div>
              <div className="bg-[#0a0a0a] rounded-lg p-4 border border-[#06D6A0] hover:border-[#2AE8B8] hover:shadow-lg hover:shadow-[#06D6A0]/30 transition-all duration-300">
                <p className="text-xs font-black text-[#2AE8B8] mb-1 uppercase tracking-wider">
                  Pakistan
                </p>
                <p className="text-2xl font-black text-[#2AE8B8]">Rs 299</p>
                <p className="text-xs text-[#2AE8B8] font-bold">PKR</p>
              </div>
            </div>
          </div>

          {/* Instructions Section */}
          <div
            className="bg-[#1a1a1a] border-2 border-[#666666] rounded-lg p-4 sm:p-6 mb-6 sm:mb-8 animate-slideInUp"
            style={{ animationDelay: "0.3s" }}
          >
            <h2 className="text-lg sm:text-xl font-black mb-4 text-white">
              How It Works
            </h2>
            <div className="space-y-3 sm:space-y-4">
              <div className="flex gap-3">
                <div className="flex-shrink-0">
                  <div className="flex items-center justify-center h-7 w-7 rounded-md bg-[#0088CC] text-white font-bold text-xs hover:bg-[#0077BB] transition-colors">
                    1
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white mb-0.5">
                    Click Dox Button
                  </h3>
                  <p className="text-xs text-[#979797] font-semibold">
                    Start your doxing submission process.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <div className="flex-shrink-0">
                  <div className="flex items-center justify-center h-7 w-7 rounded-md bg-[#0088CC] text-white font-bold text-xs hover:bg-[#0077BB] transition-colors">
                    2
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white mb-0.5">
                    Discord Ticket
                  </h3>
                  <p className="text-xs text-[#979797] font-semibold">
                    Create a support ticket on Discord with details.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <div className="flex-shrink-0">
                  <div className="flex items-center justify-center h-7 w-7 rounded-md bg-[#0088CC] text-white font-bold text-xs hover:bg-[#0077BB] transition-colors">
                    3
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white mb-0.5">
                    Prepare Content
                  </h3>
                  <p className="text-xs text-[#979797] font-semibold">
                    Gather photo and details for verification.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <div className="flex-shrink-0">
                  <div className="flex items-center justify-center h-7 w-7 rounded-md bg-[#0088CC] text-white font-bold text-xs hover:bg-[#0077BB] transition-colors">
                    4
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white mb-0.5">
                    Payment
                  </h3>
                  <p className="text-xs text-[#979797] font-semibold">
                    Complete payment. Moderators verify submission.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <div className="flex-shrink-0">
                  <div className="flex items-center justify-center h-7 w-7 rounded-md bg-[#0088CC] text-white font-bold text-xs hover:bg-[#0077BB] transition-colors">
                    5
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white mb-0.5">
                    Publish
                  </h3>
                  <p className="text-xs text-[#979797] font-semibold">
                    After verification, post goes live on website.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Call to Action */}
          <div
            className="text-center mt-4 sm:mt-6 animate-popIn"
            style={{ animationDelay: "0.4s" }}
          >
            <button
              onClick={handleDoxNow}
              className="inline-flex items-center gap-2 px-5 sm:px-6 py-2.5 sm:py-3 bg-[#0088CC] text-white font-bold text-sm rounded-lg hover:bg-[#0077BB] shadow-md hover:shadow-lg hover:shadow-[#0088CC]/40 transition-all duration-300 transform hover:scale-105 active:scale-95"
            >
              Dox Now
              <ArrowRight className="w-3 h-3 sm:w-4 sm:h-4" />
            </button>
            <div className="mt-4 sm:mt-6">
              <a
                href="https://discord.gg/95eC83gtFN"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#0088CC] hover:text-[#00C4FF] font-semibold text-sm transition-colors duration-300"
              >
                Or join our Discord community
              </a>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}
