import { useScroll, useTransform, useSpring } from 'framer-motion';
import { useMemo } from 'react';

export function useScrollTheme() {
  const { scrollYProgress } = useScroll();
  
  // A spring for smooth color transitions
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  // Map scroll progress to background color transition
  // 0% -> #07080b (Dark Hero)
  // 15% -> #f7f8fb (Light Mode reveal)
  // 100% -> #ffffff (Pure white at the bottom)
  const backgroundColor = useTransform(
    smoothProgress,
    [0, 0.15, 0.8, 1],
    ['#07080b', '#f7f8fb', '#f7f8fb', '#ffffff']
  );
  
  // Keep text contrasting
  const textColor = useTransform(
    smoothProgress,
    [0, 0.1, 0.15],
    ['#ffffff', '#ffffff', '#12131a']
  );

  return useMemo(() => ({ backgroundColor, textColor, scrollYProgress }), [backgroundColor, textColor, scrollYProgress]);
}
