import tkinter as tk
from tkinter import messagebox, simpledialog, Text
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class DigitalSignaturesApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Digital Signatures App")
        self.master.geometry("400x250")

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
            self.main_frame, text="Verify Signature", command=self.verify_signature, width=15)
        self.verify_button.grid(row=3, column=0, padx=10, pady=10)

        # Use RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def generate_signature(self):
        try:
            message_to_sign = self.message_entry.get().encode('utf-8')
            signature = self.private_key.sign(
                message_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.signature_text.config(state="normal")
            self.signature_text.delete("1.0", tk.END)
            self.signature_text.insert(tk.END, f"{signature.hex()}\n")
            self.signature_text.config(state="disabled")

            # Enable Copy to Clipboard button
            self.copy_button.config(state="normal")

            messagebox.showinfo("Signature Generated",
                                "Digital signature has been generated.")

        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to generate signature: {str(e)}")

    def copy_signature(self):
        try:
            signature_text = self.signature_text.get("1.0", tk.END)
            if signature_text:
                self.master.clipboard_clear()
                self.master.clipboard_append(signature_text)
                messagebox.showinfo("Signature Copied",
                                    "Signature copied to clipboard.")
            else:
                messagebox.showwarning("No Signature", "No signature to copy.")

        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to copy signature: {str(e)}")

    def verify_signature(self):
        try:
            message_to_verify = self.message_entry.get().encode('utf-8')
            signature_str = simpledialog.askstring("Input", "Enter signature:")

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
            messagebox.showerror(
                "Error", f"Signature Invalid: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignaturesApp(root)
    root.mainloop()
