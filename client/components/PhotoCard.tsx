import { useState } from "react";
import { Download } from "lucide-react";

interface PhotoCardProps {
  url: string;
  name: string;
  index: number;
  total: number;
  onDownload: () => void;
}

export default function PhotoCard({
  url,
  name,
  index,
  total,
  onDownload,
}: PhotoCardProps) {
  const [imgError, setImgError] = useState(false);
  const [imgLoading, setImgLoading] = useState(true);

  return (
    <div className="group relative rounded-lg overflow-hidden border border-[#666666] hover:border-[#0088CC] transition-all duration-300 bg-[#1a1a1a] h-full flex flex-col">
      {/* Image Container */}
      <div className="relative w-full aspect-square overflow-hidden bg-[#0a0a0a] flex-shrink-0">
        {!imgError ? (
          <>
            {imgLoading && (
              <div className="absolute inset-0 bg-[#0a0a0a] flex items-center justify-center z-10">
                <div className="w-5 h-5 sm:w-6 sm:h-6 border-2 border-[#666666] border-t-[#0088CC] rounded-full animate-spin"></div>
              </div>
            )}
            <img
              src={url}
              alt={name}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
              loading="lazy"
              decoding="async"
              crossOrigin="anonymous"
              onLoad={() => setImgLoading(false)}
              onError={() => {
                setImgLoading(false);
                setImgError(true);
              }}
            />
          </>
        ) : (
          <div className="absolute inset-0 bg-[#0a0a0a] flex flex-col items-center justify-center gap-1 sm:gap-2">
            <div className="text-xl sm:text-2xl">🖼️</div>
            <p className="text-[#666666] text-xs text-center px-2">
              Image unavailable
            </p>
          </div>
        )}

        {/* Hover Overlay */}
        <div className="absolute inset-0 bg-black/0 group-hover:bg-black/40 transition-colors duration-300 flex items-center justify-center opacity-0 group-hover:opacity-100 pointer-events-none">
          <div className="bg-black/80 px-2 sm:px-3 py-1 sm:py-1.5 rounded text-white text-xs font-medium">
            {index + 1} / {total}
          </div>
        </div>
      </div>

      {/* Photo Info and Download Button */}
      <div className="p-2 sm:p-3 space-y-2 sm:space-y-3 border-t border-[#666666] flex-1 flex flex-col justify-end">
        <p className="text-xs font-semibold text-white truncate break-words line-clamp-2">
          {name}
        </p>

        <button
          onClick={onDownload}
          className="w-full px-2 sm:px-3 py-2 bg-[#0088CC] hover:bg-[#0077BB] text-white text-xs sm:text-sm font-medium rounded transition-all active:scale-95 flex items-center justify-center gap-2 touch-target min-h-[44px]"
        >
          <Download className="w-3 h-3 sm:w-4 sm:h-4" />
          <span>Download</span>
        </button>
      </div>
    </div>
  );
}
