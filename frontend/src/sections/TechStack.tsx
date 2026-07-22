import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { 
  SiReact, SiNextdotjs, SiTypescript, SiNodedotjs, 
  SiPostgresql, SiDocker, SiGithub, SiKubernetes, 
  SiGo, SiPython, SiVercel, SiGooglecloud 
} from 'react-icons/si';

const TECHS = [
  { icon: SiReact, name: "React" },
  { icon: SiNextdotjs, name: "Next.js" },
  { icon: SiTypescript, name: "TypeScript" },
  { icon: SiNodedotjs, name: "Node.js" },
  { icon: SiPython, name: "Python" },
  { icon: SiGo, name: "Go" },
  { icon: SiPostgresql, name: "PostgreSQL" },
  { icon: SiDocker, name: "Docker" },
  { icon: SiKubernetes, name: "Kubernetes" },
  { icon: SiGithub, name: "GitHub" },
  { icon: SiVercel, name: "Vercel" },
  { icon: SiGooglecloud, name: "GCP" },
];

export function TechStack() {
  const prefersReducedMotion = useReducedMotion();
  
  // Duplicate array for seamless loop
  const duplicatedTechs = [...TECHS, ...TECHS];

  return (
    <section className="py-24 overflow-hidden bg-white border-y border-[#12131a]/5">
      <div className="max-w-7xl mx-auto px-6 mb-12 text-center">
        <h2 className="font-serif text-3xl font-bold text-[#12131a]">
          S'intègre à votre stack
        </h2>
      </div>

      <div className="relative flex overflow-x-hidden group">
        <motion.div
          className="flex whitespace-nowrap gap-16 px-8 items-center"
          animate={prefersReducedMotion ? {} : { x: ["0%", "-50%"] }}
          transition={
            prefersReducedMotion
              ? {}
              : {
                  repeat: Infinity,
                  ease: "linear",
                  duration: 40, // 30% slower could be adjusted here based on screen size, but css/framer approaches differ. We'll use a solid duration.
                }
          }
          style={{ width: "max-content" }}
        >
          {duplicatedTechs.map((tech, idx) => (
            <div 
              key={idx} 
              className="flex items-center gap-3 text-[#8a8d9c] hover:text-[#1d4ed8] transition-colors duration-300"
            >
              <tech.icon className="w-10 h-10" />
              <span className="font-semibold text-lg">{tech.name}</span>
            </div>
          ))}
        </motion.div>
        
        {/* Gradients for fade effect on edges */}
        <div className="absolute top-0 bottom-0 left-0 w-32 bg-gradient-to-r from-white to-transparent pointer-events-none" />
        <div className="absolute top-0 bottom-0 right-0 w-32 bg-gradient-to-l from-white to-transparent pointer-events-none" />
      </div>
    </section>
  );
}
