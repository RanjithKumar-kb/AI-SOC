import platform
import time

def trigger_alarm_sound(repeats: int = 3, frequency: int = 2500, duration_ms: int = 300):
    """
    Triggers an OS-level audio alarm sound when critical threats or VPN connections are flagged.
    """
    print("🚨 [ALARM ENGINE] System Siren Activated!")
    
    current_os = platform.system()
    
    for _ in range(repeats):
        if current_os == "Windows":
            import winsound
            # Alternating pitch for a siren effect
            winsound.Beep(frequency, duration_ms)
            winsound.Beep(frequency - 500, duration_ms)
        else:
            # Unix / macOS terminal audio bell
            print("\a", end="", flush=True)
            time.sleep(0.3)