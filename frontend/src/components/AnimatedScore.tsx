/**
 * AnimatedScore — Affiche le Security Score avec un compteur animé
 * de 0 vers la valeur finale lors de l'apparition.
 *
 * Respecte prefers-reduced-motion : si activé, affiche directement la valeur.
 */
import React, { useEffect, useRef, useState } from "react";

interface AnimatedScoreProps {
  value: number;
  isNull?: boolean;
  duration?: number; // ms
  className?: string;
  style?: React.CSSProperties;
}

export function AnimatedScore({
  value,
  isNull = false,
  duration = 1200,
  className = "",
  style,
}: AnimatedScoreProps) {
  const [displayed, setDisplayed] = useState(0);
  const frameRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);

  // Respect prefers-reduced-motion
  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    if (isNull) return;
    if (prefersReduced) {
      setDisplayed(value);
      return;
    }

    startRef.current = null;
    const from = 0;
    const to = value;

    function step(ts: number) {
      if (startRef.current === null) startRef.current = ts;
      const elapsed = ts - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayed(Math.round(from + (to - from) * eased));
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(step);
      }
    }

    frameRef.current = requestAnimationFrame(step);
    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    };
  }, [value, isNull, duration, prefersReduced]);

  if (isNull) return <span className={className} style={style}>N/A</span>;
  return <span className={className} style={style}>{displayed}</span>;
}
