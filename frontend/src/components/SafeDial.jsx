import React, { useState, useEffect, useRef } from 'react';
import styles from './SafeDial.module.css';

const ALPHABET = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '@', '#', '$', '%', '&', '*', '?', '!', '+', '=', '-', '_', '[', ']'
]; // 50 characters

export default function SafeDial({ combination, onChange, onComplete }) {
  const [rotation, setRotation] = useState(0);
  const [currentVal, setCurrentVal] = useState(ALPHABET[0]);
  const [enteredCombo, setEnteredCombo] = useState([null, null, null]);
  const [activeSlot, setActiveSlot] = useState(0);
  const [direction, setDirection] = useState('none');
  const [instruction, setInstruction] = useState('');

  const dialRef = useRef(null);
  const isDragging = useRef(false);
  const startAngle = useRef(0);
  const startRotation = useRef(0);
  const lastMouseAngle = useRef(0);
  const audioCtxRef = useRef(null);
  
  const rotationRef = useRef(0); // Synchronous source of truth for rotation

  const lastDirection = useRef('none');
  const movementHistory = useRef([]);
  const peakRotation = useRef(0);
  const lastLoggedVal = useRef(ALPHABET[0]);

  useEffect(() => {
    updateInstruction(0);
  }, []);

  useEffect(() => {
    if (combination && combination.every(v => v === null)) {
      resetDial();
    }
  }, [combination]);

  const playTickSound = (type = 'tick') => {
    try {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)();
      }
      
      const ctx = audioCtxRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const osc = ctx.createOscillator();
      const gainNode = ctx.createGain();

      osc.connect(gainNode);
      gainNode.connect(ctx.destination);

      if (type === 'tick') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1200, ctx.currentTime);
        gainNode.gain.setValueAtTime(0.015, ctx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.05);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.05);
      } else if (type === 'lock') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(150, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(60, ctx.currentTime + 0.15);
        gainNode.gain.setValueAtTime(0.1, ctx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.15);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.15);
      }
    } catch (e) {
      // Audio failed
    }
  };

  const updateInstruction = (slotIndex) => {
    if (slotIndex === 0) {
      setInstruction('Spin RIGHT (Clockwise) to your 1st character, then reverse direction to lock it.');
    } else if (slotIndex === 1) {
      setInstruction('Spin LEFT (Counter-Clockwise) to your 2nd character, then reverse direction to lock it.');
    } else if (slotIndex === 2) {
      setInstruction('Spin RIGHT (Clockwise) to your 3rd character, then reverse direction to lock it.');
    } else {
      setInstruction('Combination fully entered! Submit to verify.');
    }
  };

  const resetDial = () => {
    rotationRef.current = 0;
    setRotation(0);
    setCurrentVal(ALPHABET[0]);
    setEnteredCombo([null, null, null]);
    setActiveSlot(0);
    setDirection('none');
    lastDirection.current = 'none';
    movementHistory.current = [];
    peakRotation.current = 0;
    updateInstruction(0);
    if (onChange) onChange([null, null, null]);
  };

  const lockNumber = (val) => {
    if (activeSlot >= 3) return;

    const newCombo = [...enteredCombo];
    newCombo[activeSlot] = val;
    setEnteredCombo(newCombo);
    playTickSound('lock');

    const nextSlot = activeSlot + 1;
    setActiveSlot(nextSlot);
    updateInstruction(nextSlot);

    if (onChange) onChange(newCombo);
    if (nextSlot === 3 && onComplete) onComplete(newCombo);

    peakRotation.current = rotationRef.current;
  };

  const handleCenterClick = (e) => {
    e.stopPropagation();
    if (activeSlot < 3) {
      lockNumber(currentVal);
    }
  };

  const getMouseAngle = (clientX, clientY) => {
    if (!dialRef.current) return 0;
    const rect = dialRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    const dx = clientX - centerX;
    const dy = clientY - centerY;
    let angle = Math.atan2(dy, dx) * (180 / Math.PI);
    return (angle + 360) % 360;
  };

  const handleStart = (clientX, clientY) => {
    isDragging.current = true;
    const angle = getMouseAngle(clientX, clientY);
    startAngle.current = angle;
    startRotation.current = rotationRef.current;
    lastMouseAngle.current = angle;
    peakRotation.current = rotationRef.current;
  };

  const handleMove = (clientX, clientY) => {
    if (!isDragging.current) return;

    const mouseAngle = getMouseAngle(clientX, clientY);
    let diff = mouseAngle - lastMouseAngle.current;

    if (diff > 180) diff -= 360;
    if (diff < -180) diff += 360;

    const newRotation = rotationRef.current + diff;
    rotationRef.current = newRotation;
    setRotation(newRotation);
    lastMouseAngle.current = mouseAngle;

    // 50 characters, so each character takes 7.2 degrees
    const count = ALPHABET.length;
    const stepAngle = 360 / count;
    const index = Math.round((360 - (newRotation % 360 + 360) % 360) / stepAngle) % count;
    const calculatedVal = ALPHABET[index];
    
    if (calculatedVal !== currentVal) {
      setCurrentVal(calculatedVal);
      if (calculatedVal !== lastLoggedVal.current) {
        playTickSound('tick');
        lastLoggedVal.current = calculatedVal;
      }
    }

    if (Math.abs(diff) > 0.1) {
      const currentDir = diff > 0 ? 'cw' : 'ccw';
      setDirection(currentDir);

      movementHistory.current.push({ dir: currentDir, rot: newRotation });
      if (movementHistory.current.length > 15) {
        movementHistory.current.shift();
      }

      if (activeSlot < 3) {
        const expectedDir = activeSlot === 1 ? 'ccw' : 'cw';
        
        if (expectedDir === 'cw') {
          if (newRotation > peakRotation.current) {
            peakRotation.current = newRotation;
          } else if (peakRotation.current - newRotation > 15) {
            const peakIndex = Math.round((360 - (peakRotation.current % 360 + 360) % 360) / stepAngle) % count;
            const peakVal = ALPHABET[peakIndex];
            lockNumber(peakVal);
          }
        } else {
          if (newRotation < peakRotation.current) {
            peakRotation.current = newRotation;
          } else if (newRotation - peakRotation.current > 15) {
            const peakIndex = Math.round((360 - (peakRotation.current % 360 + 360) % 360) / stepAngle) % count;
            const peakVal = ALPHABET[peakIndex];
            lockNumber(peakVal);
          }
        }
      }
    }
  };

  const handleEnd = () => {
    isDragging.current = false;
    setDirection('none');
  };

  const onMouseDown = (e) => {
    handleStart(e.clientX, e.clientY);
  };

  const onTouchStart = (e) => {
    if (e.touches.length === 1) {
      handleStart(e.touches[0].clientX, e.touches[0].clientY);
    }
  };

  useEffect(() => {
    const handleGlobalMouseMove = (e) => {
      if (isDragging.current) handleMove(e.clientX, e.clientY);
    };

    const handleGlobalTouchMove = (e) => {
      if (isDragging.current && e.touches.length === 1) {
        handleMove(e.touches[0].clientX, e.touches[0].clientY);
      }
    };

    const handleGlobalMouseUp = () => {
      handleEnd();
    };

    window.addEventListener('mousemove', handleGlobalMouseMove);
    window.addEventListener('mouseup', handleGlobalMouseUp);
    window.addEventListener('touchmove', handleGlobalTouchMove);
    window.addEventListener('touchend', handleGlobalMouseUp);

    return () => {
      window.removeEventListener('mousemove', handleGlobalMouseMove);
      window.removeEventListener('mouseup', handleGlobalMouseUp);
      window.removeEventListener('touchmove', handleGlobalTouchMove);
      window.removeEventListener('touchend', handleGlobalMouseUp);
    };
  }, [activeSlot, currentVal, enteredCombo]);

  const renderTicks = () => {
    const ticks = [];
    const count = ALPHABET.length;
    const stepAngle = 360 / count;

    for (let i = 0; i < count; i++) {
      const angle = i * stepAngle;
      const isMajor = i % 5 === 0;
      
      const r1 = 135;
      const r2 = isMajor ? 122 : 128;
      
      const angleRad = (angle - 90) * (Math.PI / 180);
      
      const x1 = 150 + r1 * Math.cos(angleRad);
      const y1 = 150 + r1 * Math.sin(angleRad);
      const x2 = 150 + r2 * Math.cos(angleRad);
      const y2 = 150 + r2 * Math.sin(angleRad);

      ticks.push(
        <line
          key={`tick-${i}`}
          x1={x1}
          y1={y1}
          x2={x2}
          y2={y2}
          className={isMajor ? styles.dialTicksMajor : styles.dialTicks}
        />
      );

      // Label every character on the dial face
      const textR = 104;
      const tx = 150 + textR * Math.cos(angleRad);
      const ty = 150 + textR * Math.sin(angleRad);
      ticks.push(
        <text
          key={`text-${i}`}
          x={tx}
          y={ty}
          className={styles.dialNumbers}
          style={{ fontSize: '11px', fontWeight: 'bold' }}
        >
          {ALPHABET[i]}
        </text>
      );
    }
    return ticks;
  };

  return (
    <div className={styles.dialContainer}>
      <p className={styles.instructionText}>{instruction}</p>
      
      <div 
        className={styles.dialWrapper}
        ref={dialRef}
        onMouseDown={onMouseDown}
        onTouchStart={onTouchStart}
      >
        <div className={styles.indicator}></div>
        
        <div className={styles.dialCenter} onClick={handleCenterClick} title="Click to manually lock current digit">
          <span className={styles.dialValue}>{currentVal}</span>
          <span className={styles.dialDirection}>
            {direction === 'none' ? 'READY' : direction}
          </span>
          <span style={{ fontSize: '9px', opacity: 0.5, color: '#aaa', marginTop: '4px' }}>
            {activeSlot < 3 ? 'TAP TO LOCK' : 'LOCKED'}
          </span>
        </div>

        <svg 
          className={styles.svgDial} 
          viewBox="0 0 300 300"
          style={{ transform: `rotate(${rotation}deg)` }}
        >
          <circle cx="150" cy="150" r="140" fill="none" stroke="#2d3238" strokeWidth="4" />
          <g>{renderTicks()}</g>
        </svg>
      </div>

      <div className={styles.combinationDisplay}>
        {[0, 1, 2].map((slot) => {
          const isFilled = enteredCombo[slot] !== null;
          const isActive = activeSlot === slot;
          return (
            <div 
              key={slot} 
              className={`${styles.comboSlot} ${
                isActive ? styles.comboSlotActive : ''
              } ${isFilled ? styles.comboSlotFilled : ''}`}
            >
              {isFilled ? enteredCombo[slot] : '__'}
            </div>
          );
        })}
      </div>

      <button type="button" className={styles.btnReset} onClick={resetDial}>
        Reset Dial
      </button>
    </div>
  );
}
