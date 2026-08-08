"use client";

import React, { useRef, useMemo, useCallback, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { cn } from "@/lib/utils";
import * as THREE from "three";

export interface BlackHoleProps {
  /** Container width */
  width?: string | number;
  /** Container height */
  height?: string | number;
  /** Additional CSS classes */
  className?: string;
  /** Content rendered above the effect */
  children?: React.ReactNode;
  /** Animation speed multiplier */
  speed?: number;
  /** Field of view scale */
  zoom?: number;
  /** Number of orbiting particles */
  particleCount?: number;
  /** Orb radius scale */
  orbSize?: number;
  /** Glow intensity per particle */
  glow?: number;
  /** Final contrast exponent */
  contrast?: number;
  /** Kaleidoscope mirror segments */
  mirrorSplits?: number;
  /** Enable kaleidoscope warp */
  warpEnabled?: boolean;
  /** Distance-based brightness multiplier */
  distanceFade?: number;
  /** Color cycle phase R */
  colorShiftR?: number;
  /** Color cycle phase G */
  colorShiftG?: number;
  /** Color cycle phase B */
  colorShiftB?: number;
  /** Per-particle color cycle speed */
  colorSpeed?: number;
  /** Background color in hex */
  backgroundColor?: string;
  /** Master opacity */
  opacity?: number;
  /** Enable cursor interaction for gravitational pull effect near pointer */
  cursorInteraction?: boolean;
  /** Cursor effect strength multiplier (0–3) */
  cursorIntensity?: number;
}

const vertexSource = `
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}
`;

const fragmentSource = `
precision highp float;
varying vec2 vUv;

uniform float uTime;
uniform vec2 uRes;
uniform float uSpeed;
uniform float uZoom;
uniform float uCount;
uniform float uOrbSize;
uniform float uGlow;
uniform float uContrast;
uniform float uSplits;
uniform bool uWarp;
uniform float uDistFade;
uniform vec3 uColorShift;
uniform float uColorRate;
uniform vec3 uBg;
uniform float uAlpha;
uniform vec2 uPointer;
uniform float uCursorActive;
uniform float uCursorIntensity;

const float TAU = 6.2831853;
const float PI = 3.14159265;

vec2 mirror(vec2 p, float seg) {
  float a = atan(p.y, p.x);
  a = ((a / PI) + 1.0) * 0.5;
  a = mod(a, 1.0 / seg) * seg;
  a = -abs(2.0 * a - 1.0) + 1.0;
  float r = length(p);
  a *= r;
  return vec2(a, r);
}

void main() {
  vec2 st = 2.0 * vUv - 1.0;
  st.x *= uRes.x / uRes.y;
  st *= uZoom;

  float dist = length(st);

  vec2 warpSt = uWarp ? st * mirror(st, uSplits) : st;

  vec2 pointerPos = (uPointer * 2.0 - 1.0) * vec2(uRes.x / uRes.y, 1.0) * uZoom;
  float cursorDist = length(st - pointerPos);
  float cursorInfluence = smoothstep(2.5, 0.0, cursorDist) * uCursorActive * uCursorIntensity;

  vec2 pullDir = normalize(pointerPos - warpSt + 0.001);
  warpSt += pullDir * cursorInfluence * 0.15;

  float localGlow = uGlow + cursorInfluence * uGlow * 0.5;
  float localDistFade = uDistFade + cursorInfluence * 0.08;

  vec3 acc = vec3(0.0);

  for (float i = 0.0; i < 30.0; i++) {
    if (i >= uCount) break;
    float t = uTime * uSpeed * 0.5 - i * PI / uCount * cos(uTime * uSpeed * 0.5 / max(i, 0.0001));
    vec2 orb = vec2(cos(t), sin(t)) / sin(i / uCount * PI / dist + uTime * uSpeed * 0.5);
    vec3 hue = cos(uColorShift * TAU / PI + PI * (uTime * uSpeed * 0.5 / (i + 1.0) * uColorRate)) * localGlow + localGlow;
    acc += dist * localDistFade / length(warpSt - orb * uOrbSize) * hue;
  }

  acc = pow(max(acc, 0.0), vec3(uContrast));

  acc += cursorInfluence * 0.03;

  float lum = dot(acc, vec3(0.299, 0.587, 0.114));
  vec3 result = mix(uBg, acc, clamp(lum * 6.0, 0.0, 1.0));

  gl_FragColor = vec4(result, uAlpha);
}
`;

interface HoleSceneProps {
  speed: number;
  zoom: number;
  particleCount: number;
  orbSize: number;
  glow: number;
  contrast: number;
  mirrorSplits: number;
  warpEnabled: boolean;
  distanceFade: number;
  colorShiftR: number;
  colorShiftG: number;
  colorShiftB: number;
  colorSpeed: number;
  backgroundColor: string;
  opacity: number;
  pointer: [number, number];
  cursorInteraction: boolean;
  cursorIntensity: number;
}

const HoleScene: React.FC<HoleSceneProps> = ({
  speed,
  zoom,
  particleCount,
  orbSize,
  glow,
  contrast,
  mirrorSplits,
  warpEnabled,
  distanceFade,
  colorShiftR,
  colorShiftG,
  colorShiftB,
  colorSpeed,
  backgroundColor,
  opacity,
  pointer,
  cursorInteraction,
  cursorIntensity,
}) => {
  const meshRef = useRef<THREE.Mesh>(null);
  const { size } = useThree();
  const smoothPointer = useRef(new THREE.Vector2(0.5, 0.5));

  const shaderUniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uRes: { value: new THREE.Vector2(1, 1) },
      uSpeed: { value: 1 },
      uZoom: { value: 1.8 },
      uCount: { value: 13 },
      uOrbSize: { value: 0.75 },
      uGlow: { value: 0.08 },
      uContrast: { value: 3 },
      uSplits: { value: 2 },
      uWarp: { value: true },
      uDistFade: { value: 0.35 },
      uColorShift: { value: new THREE.Vector3(-6, -6, -6) },
      uColorRate: { value: 0.2 },
      uBg: { value: new THREE.Vector3(0, 0, 0) },
      uAlpha: { value: 1 },
      uPointer: { value: new THREE.Vector2(0.5, 0.5) },
      uCursorActive: { value: 0 },
      uCursorIntensity: { value: 1 },
    }),
    [],
  );

  useFrame((state, delta) => {
    if (!meshRef.current) return;
    const mat = meshRef.current.material as THREE.ShaderMaterial;
    mat.uniforms.uTime.value = state.clock.elapsedTime;
    mat.uniforms.uRes.value.set(size.width, size.height);
    mat.uniforms.uSpeed.value = speed;
    mat.uniforms.uZoom.value = zoom;
    mat.uniforms.uCount.value = particleCount;
    mat.uniforms.uOrbSize.value = orbSize;
    mat.uniforms.uGlow.value = glow;
    mat.uniforms.uContrast.value = contrast;
    mat.uniforms.uSplits.value = mirrorSplits;
    mat.uniforms.uWarp.value = warpEnabled;
    mat.uniforms.uDistFade.value = distanceFade;
    mat.uniforms.uColorShift.value.set(colorShiftR, colorShiftG, colorShiftB);
    mat.uniforms.uColorRate.value = colorSpeed;
    const bg = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(
      backgroundColor,
    );
    if (bg)
      mat.uniforms.uBg.value.set(
        parseInt(bg[1], 16) / 255,
        parseInt(bg[2], 16) / 255,
        parseInt(bg[3], 16) / 255,
      );
    mat.uniforms.uAlpha.value = opacity;
    mat.uniforms.uCursorActive.value = cursorInteraction ? 1 : 0;
    mat.uniforms.uCursorIntensity.value = cursorIntensity;

    const ease = 1 - Math.exp(-delta / 0.15);
    smoothPointer.current.x += (pointer[0] - smoothPointer.current.x) * ease;
    smoothPointer.current.y += (pointer[1] - smoothPointer.current.y) * ease;
    mat.uniforms.uPointer.value.set(
      smoothPointer.current.x,
      smoothPointer.current.y,
    );
  });

  return (
    <mesh ref={meshRef}>
      <planeGeometry args={[2, 2]} />
      <shaderMaterial
        vertexShader={vertexSource}
        fragmentShader={fragmentSource}
        uniforms={shaderUniforms}
        transparent
      />
    </mesh>
  );
};

const BlackHole: React.FC<BlackHoleProps> = ({
  width = "100%",
  height = "100%",
  className,
  children,
  speed = 1,
  zoom = 1.8,
  particleCount = 13,
  orbSize = 0.75,
  glow = 0.08,
  contrast = 3,
  mirrorSplits = 2,
  warpEnabled = true,
  distanceFade = 0.35,
  colorShiftR = -6,
  colorShiftG = -6,
  colorShiftB = -6,
  colorSpeed = 0.2,
  backgroundColor = "#000000",
  opacity = 1,
  cursorInteraction = false,
  cursorIntensity = 1,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [pointer, setPointer] = useState<[number, number]>([0.5, 0.5]);

  const handlePointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!cursorInteraction) return;
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const nx = (e.clientX - rect.left) / rect.width;
      const ny = 1 - (e.clientY - rect.top) / rect.height;
      setPointer([nx, ny]);
    },
    [cursorInteraction],
  );

  return (
    <div
      ref={containerRef}
      className={cn("relative overflow-hidden", className)}
      style={{ width, height }}
      onPointerMove={handlePointerMove}
    >
      <Canvas
        className="absolute inset-0"
        gl={{ antialias: true, alpha: true }}
        orthographic
        camera={{
          position: [0, 0, 1],
          zoom: 1,
          left: -1,
          right: 1,
          top: 1,
          bottom: -1,
        }}
      >
        <HoleScene
          speed={speed}
          zoom={zoom}
          particleCount={particleCount}
          orbSize={orbSize}
          glow={glow}
          contrast={contrast}
          mirrorSplits={mirrorSplits}
          warpEnabled={warpEnabled}
          distanceFade={distanceFade}
          colorShiftR={colorShiftR}
          colorShiftG={colorShiftG}
          colorShiftB={colorShiftB}
          colorSpeed={colorSpeed}
          backgroundColor={backgroundColor}
          opacity={opacity}
          pointer={pointer}
          cursorInteraction={cursorInteraction}
          cursorIntensity={cursorIntensity}
        />
      </Canvas>
      {children && <div className="relative z-10">{children}</div>}
    </div>
  );
};

BlackHole.displayName = "BlackHole";

export default BlackHole;
