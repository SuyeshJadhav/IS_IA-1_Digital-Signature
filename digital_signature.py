import tkinter as tk
from tkinter import Text, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def center_window(window, width, height):
    """Center the given window on the screen."""
    # Get the screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # Calculate x and y coordinates to center the window
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

    # Set the window's position
    window.geometry(f"{width}x{height}+{x}+{y}")


class DigitalSignaturesApp:
    """A class representing a Digital Signatures Application."""

    def __init__(self, master):
        """Initialize the DigitalSignaturesApp."""
        self.master = master
        self.master.title("Digital Signature")

        # Set the dimensions of the main window
        self.master_width = 400
        self.master_height = 250
        self.master.geometry(f"{self.master_width}x{self.master_height}")

        # Disable window resizing
        self.master.resizable(False, False)

        # Position the main window at the center of the display
        center_window(self.master, self.master_width, self.master_height)

        # Create a frame for organized layout
        self.main_frame = tk.Frame(master)
        self.main_frame.pack(padx=20, pady=20)

        # Message entry field
        self.message_label = tk.Label(self.main_frame, text="Enter message:")
        self.message_label.grid(row=0, column=0, sticky=tk.W)

        self.message_entry = tk.Entry(self.main_frame, width=30)
        self.message_entry.grid(row=0, column=1, padx=10, pady=10)

        # Signature display
        self.signature_label = tk.Label(
            self.main_frame, text="Generated Signature:")
        self.signature_label.grid(row=1, column=0, sticky=tk.W)

        self.signature_text = Text(self.main_frame, height=3, width=30)
        self.signature_text.grid(row=1, column=1, padx=10, pady=10)

        # Generate Signature button
        self.generate_button = tk.Button(
            self.main_frame, text="Generate Signature", command=self.generate_signature, width=15)
        self.generate_button.grid(row=2, column=0, padx=10, pady=10)

        # Copy to Clipboard button
        self.copy_button = tk.Button(
            self.main_frame, text="Copy to Clipboard", command=self.copy_signature, width=15, state="disabled")
        self.copy_button.grid(row=2, column=1, padx=10, pady=10)

        # Verify button
        self.verify_button = tk.Button(
            self.main_frame, text="Verify Signature", command=self.open_verification_window, width=15)
        self.verify_button.grid(row=3, column=0, padx=10, pady=10)

        # Use RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        # Verification window
        self.verify_window = None
        self.verify_entry = None

    def open_verification_window(self):
        """Open the verification window."""
        if self.verify_window is None:
            self.verify_window = tk.Toplevel(self.master)
            self.verify_window.title(
                "Verify Signature")

            # Set dimensions of the verification window
            verify_window_width = 400
            verify_window_height = 250

            # Position the verification window at the center of the display
            center_window(self.verify_window,
                          verify_window_width, verify_window_height)

            # Frame for organizing widgets
            verification_frame = tk.Frame(self.verify_window)
            verification_frame.pack(expand=True, padx=20, pady=20)

            # Input field for signature
            signature_entry_label = tk.Label(
                verification_frame, text="Enter signature:")
            signature_entry_label.grid(
                row=0, column=0, padx=10, pady=10)

            self.verify_entry = tk.Entry(
                verification_frame, width=50)  # Use Entry widget for single line input
            self.verify_entry.grid(
                row=0, column=1, padx=10, pady=10, columnspan=2)  # Span two columns

            # Verify button
            verify_signature_button = tk.Button(
                verification_frame, text="Verify", command=self.verify, width=10)  # Reduce button width
            verify_signature_button.grid(
                row=1, column=1, padx=5, pady=10)  # Adjust padding

            # Center the button in the window
            verification_frame.grid_columnconfigure(1, weight=1)

        else:
            self.verify_window.deiconify()  # Bring the window to the front

    def verify(self):
        """Verify the signature."""
        try:
            if self.verify_entry is None:
                raise ValueError("Verification entry field is not initialized")

            message_to_verify = self.message_entry.get().encode('utf-8')
            signature_str = self.verify_entry.get()

            if not signature_str:
                raise ValueError("Please enter a signature.")

            signature = bytes.fromhex(signature_str)
            self.public_key.verify(
                signature,
                message_to_verify,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            messagebox.showinfo("Verification Result", "Signature is valid.")

        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")

        except Exception as e:
            messagebox.showerror("Error", f"Signature Invalid: {str(e)}")

            if self.verify_window is not None:
                self.verify_window.destroy()
                self.verify_window = None

    def generate_signature(self):
        """Generate a digital signature."""
        try:
            message_to_sign = self.message_entry.get().encode('utf-8')
            signature = self.private_key.sign(
                message_to_sign,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self.signature_text.config(state="normal")
            self.signature_text.delete("1.0", tk.END)
            self.signature_text.insert(tk.END, f"{signature.hex()}\n")
            self.signature_text.config(state="disabled")

            # Enable Copy to Clipboard button
            self.copy_button.config(state="normal")

        except Exception as e:
            print(f"Failed to generate signature: {str(e)}")

    def copy_signature(self):
        """Copy the generated signature to the clipboard."""
        try:
            signature_text = self.signature_text.get("1.0", tk.END)
            if signature_text:
                self.master.clipboard_clear()
                self.master.clipboard_append(signature_text)
            else:
                print("No signature to copy.")

        except Exception as e:
            print(f"Failed to copy signature: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignaturesApp(root)
    root.mainloop()
