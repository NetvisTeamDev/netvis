// netvis.cc front-end behaviour.
//
// Kept as a separate file rather than an inline <script> so the site can run
// under a Content-Security-Policy of script-src 'self' - no 'unsafe-inline',
// no hashes to keep in sync every time a line changes here.
(function () {
  "use strict";

  var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var canHover = window.matchMedia && window.matchMedia("(hover: hover)").matches;

  // ---- reveal on scroll -------------------------------------------------
  // IntersectionObserver rather than a scroll handler, so the browser isn't
  // recalculating layout on every frame.
  var items = document.querySelectorAll(".reveal");
  if (still || !("IntersectionObserver" in window)) {
    Array.prototype.forEach.call(items, function (el) { el.classList.add("shown"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("shown"); io.unobserve(e.target); }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -50px 0px" });
    Array.prototype.forEach.call(items, function (el) { io.observe(el); });
  }

  // ---- scroll progress + nav condense -----------------------------------
  var bar = document.getElementById("progressBar");
  var nav = document.getElementById("nav");
  var ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      var h = document.documentElement.scrollHeight - window.innerHeight;
      var p = h > 0 ? window.scrollY / h : 0;
      if (bar) bar.style.transform = "scaleX(" + p.toFixed(4) + ")";
      if (nav) nav.classList.toggle("solid", window.scrollY > 12);
      ticking = false;
    });
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // ---- cursor ------------------------------------------------------------
  // An aura pinned to the pointer, a ring that trails behind it, and packets
  // that peel off as you move - the same visual language as the traffic
  // graph, so the page feels like the product.
  //
  // The whole thing is built in script and only on a device that actually has
  // a pointer: on a phone none of these nodes ever exist, and the OS cursor is
  // never hidden, so if this fails there is still an arrow on screen.
  if (canHover && !still) {
    var layer = document.getElementById("cursorfx");
    if (layer) {
      var aura = document.createElement("i"); aura.className = "cur-aura";
      var ring = document.createElement("i"); ring.className = "cur-ring";
      layer.appendChild(aura); layer.appendChild(ring);

      var POOL = 16, packets = [], pi = 0;
      for (var k = 0; k < POOL; k++) {
        var p = document.createElement("i");
        p.className = "cur-packet";
        layer.appendChild(p);
        packets.push({ el: p, life: 0, x: 0, y: 0, vx: 0, vy: 0 });
      }

      var mx = -200, my = -200;        // where the pointer is
      var ax = mx, ay = my;            // aura, close behind
      var rx = mx, ry = my;            // ring, further behind
      var lastEmitX = mx, lastEmitY = my;
      var alive = false, idle = 0, running = false;

      document.addEventListener("pointermove", function (e) {
        if (e.pointerType === "touch") return;
        mx = e.clientX; my = e.clientY;
        if (!alive) { alive = true; ax = rx = mx; ay = ry = my; layer.classList.add("vis"); }
        idle = 0;
        start();
      }, { passive: true });

      document.addEventListener("pointerdown", function () { layer.classList.add("down"); });
      document.addEventListener("pointerup", function () { layer.classList.remove("down"); });
      document.addEventListener("pointerleave", function () { layer.classList.remove("vis"); });

      // Anything clickable makes the ring open up, so the cursor answers
      // "can I press this?" before the hover state does.
      //
      // Decided from pointerover alone rather than an over/out pair: moving
      // from a button's inner <span> to the button itself fires out-then-over,
      // and toggling a class on each would blink the ring for a frame.
      // pointerover fires on whatever is now under the pointer, so asking it
      // once, every time, is both simpler and steadier.
      var HOT = "a, button, .btn, .plan, .pain-card, .feature-shot, .comm-card, input";
      document.addEventListener("pointerover", function (e) {
        var t = e.target;
        layer.classList.toggle("hot", !!(t && t.closest && t.closest(HOT)));
      });

      function emit(dist) {
        var s = packets[pi]; pi = (pi + 1) % POOL;
        s.life = 1;
        s.x = mx + (Math.random() - 0.5) * 6;
        s.y = my + (Math.random() - 0.5) * 6;
        // Thrown gently against the direction of travel, like something
        // shedding off the back of a moving object.
        s.vx = (lastEmitX - mx) / Math.max(dist, 1) * 0.9 + (Math.random() - 0.5) * 0.7;
        s.vy = (lastEmitY - my) / Math.max(dist, 1) * 0.9 + (Math.random() - 0.5) * 0.7;
        s.el.classList.toggle("up", Math.random() < 0.35);
      }

      function frame() {
        ax += (mx - ax) * 0.34;
        ay += (my - ay) * 0.34;
        rx += (mx - rx) * 0.15;
        ry += (my - ry) * 0.15;
        aura.style.transform = "translate3d(" + ax + "px," + ay + "px,0)";
        ring.style.transform = "translate3d(" + rx + "px," + ry + "px,0)";

        var dx = mx - lastEmitX, dy = my - lastEmitY;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > 14) { emit(dist); lastEmitX = mx; lastEmitY = my; }

        var busy = false;
        for (var i = 0; i < POOL; i++) {
          var s = packets[i];
          if (s.life <= 0) { continue; }
          busy = true;
          s.life -= 0.028;
          s.x += s.vx; s.y += s.vy;
          s.vx *= 0.94; s.vy *= 0.94;
          if (s.life <= 0) { s.el.style.opacity = "0"; continue; }
          s.el.style.opacity = (s.life * 0.85).toFixed(3);
          s.el.style.transform = "translate3d(" + s.x + "px," + s.y + "px,0) scale(" +
                                 (0.5 + s.life * 0.7).toFixed(3) + ")";
        }

        // Wind down when nothing is moving, so an idle tab isn't burning a
        // frame callback forever.
        idle++;
        if (!busy && idle > 90 && Math.abs(mx - rx) < 0.5 && Math.abs(my - ry) < 0.5) {
          running = false;
          return;
        }
        requestAnimationFrame(frame);
      }

      function start() { if (!running) { running = true; requestAnimationFrame(frame); } }
    }
  }

  // ---- cursor spotlight on cards ----------------------------------------
  // Sets two custom properties the CSS uses to position a soft highlight.
  if (!still && canHover) {
    Array.prototype.forEach.call(document.querySelectorAll(".spot > *"), function (card) {
      card.addEventListener("pointermove", function (e) {
        var r = card.getBoundingClientRect();
        card.style.setProperty("--mx", (e.clientX - r.left) + "px");
        card.style.setProperty("--my", (e.clientY - r.top) + "px");
      });
    });
  }

  // ---- hero screenshot tilt ---------------------------------------------
  var hero = document.getElementById("heroShot");
  if (hero && !still && canHover) {
    var raf = null, tx = 0, ty = 0;
    hero.addEventListener("pointermove", function (e) {
      var r = hero.getBoundingClientRect();
      tx = ((e.clientX - r.left) / r.width - 0.5) * 2;   // -1 .. 1
      ty = ((e.clientY - r.top) / r.height - 0.5) * 2;
      if (raf) return;
      raf = requestAnimationFrame(function () {
        raf = null;
        hero.style.transform =
          "perspective(1200px) rotateY(" + (tx * 3.2).toFixed(2) + "deg) rotateX(" +
          (-ty * 2.4).toFixed(2) + "deg) translateY(-6px)";
      });
    });
    hero.addEventListener("pointerleave", function () { hero.style.transform = ""; });
  }

  // ---- ping bars: play when seen, not on load ---------------------------
  if (!still && "IntersectionObserver" in window) {
    var bio = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("play"); bio.unobserve(e.target); }
      });
    }, { threshold: 0.4 });
    Array.prototype.forEach.call(document.querySelectorAll(".bars"), function (el) { bio.observe(el); });
  } else {
    Array.prototype.forEach.call(document.querySelectorAll(".bars"), function (el) { el.classList.add("play"); });
  }

  // ---- the live hero trace ----------------------------------------------
  // The same idea as the graph in the app: a fixed window of samples that
  // scrolls left as new ones arrive. Rather than redrawing every frame, the
  // whole group is translated by exactly one column per tick and the data is
  // shifted when that translation finishes - so the motion is a single
  // compositor transform, and the redraw happens at 1.4Hz instead of 60.
  var N = 42, W = 820, H = 120, STEP = W / (N - 2), TICK = 1400;
  var shift = document.getElementById("traceShift");
  var down = [], up = [];

  function nextSample(prev, base, spike) {
    var v = prev + (Math.random() - 0.5) * base * 0.5;
    if (Math.random() < spike) v += base * (1 + Math.random() * 2.2);
    v += (base - v) * 0.12;                       // pull back toward the baseline
    return Math.max(base * 0.06, Math.min(1, v));
  }
  for (var i = 0; i < N; i++) {
    down.push(nextSample(down.length ? down[down.length - 1] : 0.22, 0.30, 0.10));
    up.push(nextSample(up.length ? up[up.length - 1] : 0.12, 0.16, 0.07));
  }

  function build(vals) {
    var line = "";
    for (var i = 0; i < vals.length; i++) {
      var x = (i * STEP).toFixed(2);
      var y = (H - vals[i] * (H - 8) - 4).toFixed(2);
      line += (i ? "L" : "M") + x + "," + y + " ";
    }
    var area = line + "L" + ((vals.length - 1) * STEP).toFixed(2) + "," + H + " L0," + H + " Z";
    return [line.trim(), area];
  }

  function paint() {
    var d = build(down), u = build(up);
    document.getElementById("dLine").setAttribute("d", d[0]);
    document.getElementById("dArea").setAttribute("d", d[1]);
    document.getElementById("uLine").setAttribute("d", u[0]);
    document.getElementById("uArea").setAttribute("d", u[1]);
  }

  function human(v, peak) {
    var bps = v * peak;
    if (bps >= 1024) return (bps / 1024).toFixed(1) + " MB/s";
    return Math.round(bps) + " KB/s";
  }

  paint();

  var rdDown = document.getElementById("rdDown"), rdUp = document.getElementById("rdUp");
  function readout() {
    if (rdDown) rdDown.textContent = human(down[down.length - 1], 5600);
    if (rdUp) rdUp.textContent = human(up[up.length - 1], 1400);
  }
  readout();

  if (!still) {
    var live = true;
    document.addEventListener("visibilitychange", function () { live = !document.hidden; });

    setInterval(function () {
      if (!live || !shift) return;
      down.push(nextSample(down[down.length - 1], 0.30, 0.10));
      up.push(nextSample(up[up.length - 1], 0.16, 0.07));

      var finish = function () {
        down.shift(); up.shift();
        shift.style.transform = "";
        paint();
        readout();
      };

      // Draw the extra column first, then slide it into place.
      paint();
      if (shift.animate) {
        var a = shift.animate(
          [{ transform: "translateX(0)" }, { transform: "translateX(" + (-STEP) + "px)" }],
          { duration: TICK, easing: "linear", fill: "none" });
        a.onfinish = finish;
      } else {
        finish();
      }
    }, TICK);
  }

  // ---- Windows-only download --------------------------------------------
  var ua = navigator.userAgent || "";
  var uaData = navigator.userAgentData;
  var isWindows = uaData ? uaData.platform === "Windows"
                         : /Windows|Win32|Win64|WOW64/i.test(ua);
  if (!isWindows) {
    var btn = document.getElementById("downloadBtn");
    btn.classList.add("disabled");
    btn.removeAttribute("href");
    btn.removeAttribute("download");
    btn.setAttribute("aria-disabled", "true");
    var isMac = uaData ? uaData.platform === "macOS" : /Mac OS X|Macintosh/i.test(ua);
    document.getElementById("downloadLabel").textContent = isMac ? "Coming to macOS" : "Windows only";
    document.getElementById("dlNote").textContent = isMac
      ? "The macOS build is still in development — join the Discord and you'll hear the moment the beta opens."
      : "netvis is Windows-only for now. Open this page on a Windows PC to download.";
    btn.addEventListener("click", function (e) { e.preventDefault(); });
  }
})();
