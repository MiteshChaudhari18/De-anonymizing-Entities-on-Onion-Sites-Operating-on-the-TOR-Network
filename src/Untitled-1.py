def run_analysis(output_text, progress, onion_url):
    def analysis():
        output_text.delete(1.0, tk.END)
        progress['value'] = 0

        if not onion_url.strip():
            safe_insert(output_text, "⚠ Please enter a valid Onion URL before starting analysis.")
            return
        if not onion_url.strip().endswith(".onion"):
            safe_insert(output_text, "❌ Only .onion domain URLs are supported for analysis.")
            return

        safe_insert(output_text, "Starting Analysis...\n")

        safe_execution(get_public_ip_and_geo, output_text, progress)
        safe_execution(tor_exit_nodes, output_text, progress)
        safe_execution(extract_metadata, output_text, progress, onion_url)

        progress['value'] = 100
        safe_insert(output_text, "\nAnalysis Complete.")

        # Reliable beep sound
        try:
            winsound.Beep(1000, 500)  # frequency: 1000 Hz, duration: 500 ms
        except Exception:
            pass

    thread = threading.Thread(target=analysis)
    thread.start()
