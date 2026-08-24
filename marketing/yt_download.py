#!/usr/bin/env python3
"""
yt_download.py - download a YouTube video in Full HD (1080p) as a single MP4.

Built on yt-dlp. Best for your own uploads or Creative-Commons content -
downloading someone else's copyrighted video breaks YouTube's terms.

First-time setup:
    pip install -U yt-dlp
    # and install ffmpeg (needed to merge 1080p video+audio into one file):
    #   Windows: winget install Gyan.FFmpeg   (then reopen the terminal)

Usage:
    python yt_download.py https://www.youtube.com/watch?v=XXXX
    python yt_download.py URL1 URL2 ...            # several at once
    python yt_download.py URL -o C:\\clips          # choose output folder
    python yt_download.py URL -q 720                # cap at 720p instead
    python yt_download.py URL --audio-only          # just the audio (mp3)
    python yt_download.py URL --no-audio            # video only, no sound
"""

import argparse
import shutil
import sys


def check_deps():
    try:
        import yt_dlp  # noqa: F401
    except ImportError:
        sys.exit("yt-dlp is not installed. Run:  pip install -U yt-dlp")
    if not shutil.which("ffmpeg"):
        print(
            "WARNING: ffmpeg not found on PATH. 1080p comes as separate video +\n"
            "         audio streams that ffmpeg merges into one file. Without it\n"
            "         you may get a lower-quality single-file format.\n"
            "         Windows: winget install Gyan.FFmpeg  (then reopen terminal)\n",
            file=sys.stderr,
        )


def build_opts(args):
    outtmpl = f"{args.output.rstrip(chr(92) + '/')}/%(title)s [%(id)s].%(ext)s"

    if args.audio_only:
        return {
            "format": "bestaudio/best",
            "outtmpl": outtmpl,
            "postprocessors": [
                {"key": "FFmpegExtractAudio", "preferredcodec": "mp3", "preferredquality": "192"}
            ],
            "noplaylist": not args.playlist,
            "ignoreerrors": len(args.urls) > 1,
        }

    q = args.quality

    if args.no_audio:
        # Video only, no sound - grabs just the video stream, so there's
        # nothing to merge and no audio track in the result. Handy for a clip
        # you'll put your own audio (or none) over.
        fmt = f"bestvideo[height<={q}][ext=mp4]/bestvideo[height<={q}]/best[height<={q}]/best"
        return {
            "format": fmt,
            "merge_output_format": "mp4",
            "outtmpl": outtmpl,
            "noplaylist": not args.playlist,
            "ignoreerrors": len(args.urls) > 1,
            "postprocessors": [{"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"}],
        }

    # Prefer an mp4 video stream up to the chosen height plus the best m4a audio,
    # so the merged file is a clean H.264/AAC MP4. Falls back gracefully if that
    # exact combo isn't offered.
    fmt = (
        f"bestvideo[height<={q}][ext=mp4]+bestaudio[ext=m4a]/"
        f"bestvideo[height<={q}]+bestaudio/"
        f"best[height<={q}]/best"
    )
    return {
        "format": fmt,
        "merge_output_format": "mp4",
        "outtmpl": outtmpl,
        "noplaylist": not args.playlist,
        "ignoreerrors": len(args.urls) > 1,  # keep going if one of several fails
        "postprocessors": [
            {"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"}
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="Download a YouTube video in Full HD (1080p).")
    ap.add_argument("urls", nargs="+", help="one or more YouTube URLs")
    ap.add_argument("-o", "--output", default=".", help="output folder (default: current)")
    ap.add_argument("-q", "--quality", type=int, default=1080,
                    help="max height in pixels (default 1080 = Full HD; e.g. 720, 1440, 2160)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--audio-only", action="store_true", help="download audio only, as mp3")
    mode.add_argument("--no-audio", action="store_true", help="download video only, no sound")
    ap.add_argument("--playlist", action="store_true",
                    help="if the URL is part of a playlist, download the whole playlist")
    args = ap.parse_args()

    check_deps()
    import yt_dlp

    opts = build_opts(args)
    with yt_dlp.YoutubeDL(opts) as ydl:
        rc = ydl.download(args.urls)
    if rc:
        sys.exit(rc)
    print("\nDone. Saved to:", args.output)


if __name__ == "__main__":
    main()
