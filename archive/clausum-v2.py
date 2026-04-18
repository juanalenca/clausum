#v2


import os
import zipfile
import sys
import io
import base64
import hashlib
import threading
from cryptography.fernet import Fernet, InvalidToken
import customtkinter as ctk
from tkinter import filedialog, messagebox


# ==============================================================================
# CONFIGURAÇÃO DO CUSTOMTKINTER
# ==============================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ==============================================================================
# CONSTANTES DE SEGURANÇA
# ==============================================================================
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000


# ==============================================================================
# CONSTANTES DE INTERFACE
# ==============================================================================
ACCENT_COLOR = "#00BCD4"
SUCCESS_COLOR = "#2ECC71"
ERROR_COLOR = "#E74C3C"
WARNING_COLOR = "#F39C12"


# ==============================================================================
# FUNÇÕES CRIPTOGRÁFICAS (BACKEND)
# ==============================================================================


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf)


def zip_source(source_path, progress_callback=None):
    in_memory_zip = io.BytesIO()
    try:
        with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isdir(source_path):
                files_list = []
                for root, _, files in os.walk(source_path):
                    for file in files:
                        files_list.append(os.path.join(root, file))
               
                total_files = len(files_list)
                for idx, file_path in enumerate(files_list):
                    archive_name = os.path.relpath(file_path, os.path.dirname(source_path))
                    zipf.write(file_path, arcname=archive_name)
                    if progress_callback:
                        progress_callback(int((idx + 1) / total_files * 50))
            elif os.path.isfile(source_path):
                archive_name = os.path.basename(source_path)
                zipf.write(source_path, arcname=archive_name)
                if progress_callback:
                    progress_callback(50)
            else:
                return None
    except Exception as e:
        print(f"Erro na compactação: {e}", file=sys.stderr)
        return None
   
    in_memory_zip.seek(0)
    return in_memory_zip.read()


def unzip_data(zip_data, destination_folder, progress_callback=None):
    try:
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
       
        in_memory_zip = io.BytesIO(zip_data)
        with zipfile.ZipFile(in_memory_zip, 'r') as zipf:
            members = zipf.namelist()
            total_files = len(members)
            for idx, member in enumerate(members):
                zipf.extract(member, destination_folder)
                if progress_callback:
                    progress_callback(50 + int((idx + 1) / total_files * 50))
        return True
    except Exception as e:
        print(f"Erro na extração: {e}", file=sys.stderr)
        return False


# ==============================================================================
# INTERFACE GRÁFICA
# ==============================================================================


class ClausumGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Clausum - Seu Cofre Digital")
        self.root.geometry("800x900")
        self.root.resizable(False, False)
       
        # Variáveis
        self.source_path = ctk.StringVar()
        self.dest_path = ctk.StringVar()
        self.backup_name = ctk.StringVar()
        self.enc_file_path = ctk.StringVar()
        self.restore_dest_path = ctk.StringVar()
       
        self.create_widgets()
   
    def create_widgets(self):
        # Container principal com padding
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
       
        # ==============================================================================
        # CABEÇALHO
        # ==============================================================================
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(pady=(0, 30))
       
        title_label = ctk.CTkLabel(
            header_frame,
            text="CLAUSUM",
            font=ctk.CTkFont(family="Courier New", size=42, weight="bold"),
            text_color=ACCENT_COLOR
        )
        title_label.pack()
       
        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Seu Cofre Digital Seguro",
            font=ctk.CTkFont(size=14),
            text_color="gray70"
        )
        subtitle_label.pack(pady=(5, 0))
       
        # ==============================================================================
        # SEGMENTED BUTTON (Tabs modernas)
        # ==============================================================================
        self.tab_var = ctk.StringVar(value="encrypt")
       
        segmented_button = ctk.CTkSegmentedButton(
            main_frame,
            values=["Criar Backup", "Restaurar Backup"],
            command=self.tab_callback,
            variable=self.tab_var,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=45
        )
        segmented_button.pack(pady=(0, 25))
        segmented_button.set("Criar Backup")
       
        # ==============================================================================
        # CONTAINER DE CONTEÚDO
        # ==============================================================================
        self.content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
       
        # Criar ambas as views
        self.create_encrypt_view()
        self.create_restore_view()
       
        # Mostrar view inicial
        self.show_encrypt_view()
   
    def tab_callback(self, value):
        if value == "Criar Backup":
            self.show_encrypt_view()
        else:
            self.show_restore_view()
   
    def show_encrypt_view(self):
        self.restore_frame.pack_forget()
        self.encrypt_frame.pack(fill="both", expand=True)
   
    def show_restore_view(self):
        self.encrypt_frame.pack_forget()
        self.restore_frame.pack(fill="both", expand=True)
   
    # ==============================================================================
    # VIEW: CRIAR BACKUP
    # ==============================================================================
    def create_encrypt_view(self):
        self.encrypt_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
       
        # Grid configuration para melhor controle
        self.encrypt_frame.grid_columnconfigure(0, weight=1)
       
        row = 0
       
        # ETAPA 1: Seleção de Origem
        step1_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="① Selecione o que deseja proteger",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step1_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        source_container = ctk.CTkFrame(self.encrypt_frame)
        source_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        source_container.grid_columnconfigure(0, weight=1)
       
        self.source_entry = ctk.CTkEntry(
            source_container,
            textvariable=self.source_path,
            placeholder_text="Nenhum arquivo ou pasta selecionado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.source_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        source_btn = ctk.CTkButton(
            source_container,
            text="📁 Selecionar",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_source
        )
        source_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 2: Nome e Destino
        step2_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="② Configure o backup",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step2_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        # Nome
        name_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="Nome do Backup:",
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        name_label.grid(row=row, column=0, sticky="w", pady=(0, 5))
        row += 1
       
        self.backup_name_entry = ctk.CTkEntry(
            self.encrypt_frame,
            textvariable=self.backup_name,
            placeholder_text="Ex: documentos_importantes",
            height=40,
            font=ctk.CTkFont(size=13)
        )
        self.backup_name_entry.grid(row=row, column=0, sticky="ew", pady=(0, 15))
        row += 1
       
        # Destino
        dest_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="Salvar Em:",
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        dest_label.grid(row=row, column=0, sticky="w", pady=(0, 5))
        row += 1
       
        dest_container = ctk.CTkFrame(self.encrypt_frame)
        dest_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        dest_container.grid_columnconfigure(0, weight=1)
       
        self.dest_entry = ctk.CTkEntry(
            dest_container,
            textvariable=self.dest_path,
            placeholder_text="Escolha onde salvar o backup criptografado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.dest_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        dest_btn = ctk.CTkButton(
            dest_container,
            text="📂 Escolher",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_dest_encrypt
        )
        dest_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 3: Senha
        step3_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="③ Crie uma senha forte",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step3_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        password_info = ctk.CTkLabel(
            self.encrypt_frame,
            text="⚠️ Use no mínimo 12 caracteres. Esta senha será necessária para restaurar o backup.",
            font=ctk.CTkFont(size=12),
            text_color=WARNING_COLOR,
            anchor="w",
            wraplength=650
        )
        password_info.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        self.password1_entry = ctk.CTkEntry(
            self.encrypt_frame,
            placeholder_text="Digite sua senha (mínimo 12 caracteres)",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.password1_entry.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        row += 1
       
        self.password2_entry = ctk.CTkEntry(
            self.encrypt_frame,
            placeholder_text="Confirme sua senha",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.password2_entry.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        row += 1
       
        # Botão Principal
        self.encrypt_btn = ctk.CTkButton(
            self.encrypt_frame,
            text="🔒 CRIPTOGRAFAR E PROTEGER",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=ACCENT_COLOR,
            hover_color="#008BA3",
            command=self.perform_encrypt
        )
        self.encrypt_btn.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        row += 1
       
        # Progress
        self.encrypt_progress = ctk.CTkProgressBar(
            self.encrypt_frame,
            height=8,
            mode="determinate"
        )
        self.encrypt_progress.set(0)
       
        self.encrypt_status = ctk.CTkLabel(
            self.encrypt_frame,
            text="",
            font=ctk.CTkFont(size=13),
            text_color="gray70"
        )
   
    # ==============================================================================
    # VIEW: RESTAURAR BACKUP
    # ==============================================================================
    def create_restore_view(self):
        self.restore_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
       
        self.restore_frame.grid_columnconfigure(0, weight=1)
       
        row = 0
       
        # ETAPA 1: Selecionar arquivo
        step1_label = ctk.CTkLabel(
            self.restore_frame,
            text="① Selecione o backup criptografado",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step1_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        enc_container = ctk.CTkFrame(self.restore_frame)
        enc_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        enc_container.grid_columnconfigure(0, weight=1)
       
        self.enc_entry = ctk.CTkEntry(
            enc_container,
            textvariable=self.enc_file_path,
            placeholder_text="Nenhum arquivo .enc selecionado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.enc_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        enc_btn = ctk.CTkButton(
            enc_container,
            text="📄 Selecionar .enc",
            width=160,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_enc_file
        )
        enc_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 2: Destino
        step2_label = ctk.CTkLabel(
            self.restore_frame,
            text="② Escolha onde restaurar",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step2_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        restore_dest_container = ctk.CTkFrame(self.restore_frame)
        restore_dest_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        restore_dest_container.grid_columnconfigure(0, weight=1)
       
        self.restore_dest_entry = ctk.CTkEntry(
            restore_dest_container,
            textvariable=self.restore_dest_path,
            placeholder_text="Pasta onde os arquivos serão restaurados",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.restore_dest_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        restore_dest_btn = ctk.CTkButton(
            restore_dest_container,
            text="📂 Escolher",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_dest_restore
        )
        restore_dest_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 3: Senha
        step3_label = ctk.CTkLabel(
            self.restore_frame,
            text="③ Digite a senha do backup",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step3_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        self.restore_password_entry = ctk.CTkEntry(
            self.restore_frame,
            placeholder_text="Senha do backup",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.restore_password_entry.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        row += 1
       
        # Botão Principal
        self.restore_btn = ctk.CTkButton(
            self.restore_frame,
            text="🔓 DESCRIPTOGRAFAR E RESTAURAR",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=ACCENT_COLOR,
            hover_color="#008BA3",
            command=self.perform_restore
        )
        self.restore_btn.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        row += 1
       
        # Progress
        self.restore_progress = ctk.CTkProgressBar(
            self.restore_frame,
            height=8,
            mode="determinate"
        )
        self.restore_progress.set(0)
       
        self.restore_status = ctk.CTkLabel(
            self.restore_frame,
            text="",
            font=ctk.CTkFont(size=13),
            text_color="gray70"
        )
   
    # ==============================================================================
    # CALLBACKS DE SELEÇÃO
    # ==============================================================================
    def select_source(self):
        path = filedialog.askdirectory(title="Selecione uma pasta")
        if not path:
            path = filedialog.askopenfilename(title="Ou selecione um arquivo")
        if path:
            self.source_path.set(path)
            if not self.backup_name.get():
                name = os.path.basename(path) + "_backup"
                self.backup_name.set(name)
   
    def select_dest_encrypt(self):
        path = filedialog.askdirectory(title="Onde salvar o backup?")
        if path:
            self.dest_path.set(path)
   
    def select_enc_file(self):
        path = filedialog.askopenfilename(
            title="Selecione o arquivo de backup",
            filetypes=[("Arquivos Clausum", "*.enc"), ("Todos os arquivos", "*.*")]
        )
        if path:
            self.enc_file_path.set(path)
   
    def select_dest_restore(self):
        path = filedialog.askdirectory(title="Onde restaurar os arquivos?")
        if path:
            self.restore_dest_path.set(path)
   
    # ==============================================================================
    # OPERAÇÕES CRIPTOGRÁFICAS
    # ==============================================================================
    def perform_encrypt(self):
        # Validações
        if not self.source_path.get():
            messagebox.showerror("Erro", "Selecione um arquivo ou pasta para backup!")
            return
       
        if not self.backup_name.get():
            messagebox.showerror("Erro", "Digite um nome para o backup!")
            return
       
        if not self.dest_path.get():
            messagebox.showerror("Erro", "Escolha onde salvar o backup!")
            return
       
        password1 = self.password1_entry.get()
        password2 = self.password2_entry.get()
       
        if len(password1) < 12:
            messagebox.showwarning("Senha Fraca", "A senha deve ter no mínimo 12 caracteres!")
            return
       
        if password1 != password2:
            messagebox.showerror("Erro", "As senhas não coincidem!")
            return
       
        # Executar em thread separada
        threading.Thread(target=self._encrypt_thread, args=(password1,), daemon=True).start()
   
    def _encrypt_thread(self, password):
        self.root.after(0, lambda: self.encrypt_btn.configure(state="disabled", text="Processando..."))
        self.root.after(0, lambda: self.encrypt_progress.grid(row=100, column=0, sticky="ew", pady=(0, 5)))
        self.root.after(0, lambda: self.encrypt_status.grid(row=101, column=0, sticky="w"))
        self.root.after(0, lambda: self.encrypt_progress.set(0))
       
        try:
            # Compactar
            self.root.after(0, lambda: self.encrypt_status.configure(text="📦 Compactando arquivos..."))
            zip_data = zip_source(
                self.source_path.get(),
                lambda p: self.root.after(0, lambda: self.encrypt_progress.set(p/100))
            )
           
            if not zip_data:
                raise Exception("Falha na compactação")
           
            # Criptografar
            self.root.after(0, lambda: self.encrypt_status.configure(text="🔐 Criptografando dados..."))
            self.root.after(0, lambda: self.encrypt_progress.set(0.75))
           
            salt = os.urandom(SALT_SIZE)
            key = derive_key(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(zip_data)
           
            # Salvar
            self.root.after(0, lambda: self.encrypt_status.configure(text="💾 Salvando arquivo protegido..."))
            self.root.after(0, lambda: self.encrypt_progress.set(0.90))
           
            filename = self.backup_name.get()
            if not filename.endswith('.enc'):
                filename += '.enc'
           
            final_path = os.path.join(self.dest_path.get(), filename)
           
            with open(final_path, 'wb') as file:
                file.write(salt)
                file.write(encrypted_data)
           
            self.root.after(0, lambda: self.encrypt_progress.set(1.0))
            self.root.after(0, lambda: self.encrypt_status.configure(
                text=f"✅ Backup criado com sucesso!",
                text_color=SUCCESS_COLOR
            ))
            self.root.after(0, lambda: messagebox.showinfo(
                "Sucesso!",
                f"Backup criptografado criado:\n\n{final_path}\n\n⚠️ Guarde sua senha em local seguro!"
            ))
           
        except Exception as e:
            self.root.after(0, lambda: self.encrypt_status.configure(
                text=f"❌ Erro: {str(e)}",
                text_color=ERROR_COLOR
            ))
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao criar backup:\n{str(e)}"))
       
        finally:
            self.root.after(0, lambda: self.encrypt_btn.configure(state="normal", text="🔒 CRIPTOGRAFAR E PROTEGER"))
   
    def perform_restore(self):
        enc_file = self.enc_file_path.get()
        restore_dest = self.restore_dest_path.get()
        password = self.restore_password_entry.get()
       
        if not enc_file:
            messagebox.showerror("Erro", "Selecione um arquivo de backup!")
            return
       
        if not restore_dest:
            messagebox.showerror("Erro", "Escolha onde restaurar os arquivos!")
            return
       
        if not password:
            messagebox.showerror("Erro", "Digite a senha do backup!")
            return
       
        threading.Thread(target=self._restore_thread, args=(enc_file, restore_dest, password), daemon=True).start()
   
    def _restore_thread(self, enc_file, restore_dest, password):
        self.root.after(0, lambda: self.restore_btn.configure(state="disabled", text="Processando..."))
        self.root.after(0, lambda: self.restore_progress.grid(row=100, column=0, sticky="ew", pady=(0, 5)))
        self.root.after(0, lambda: self.restore_status.grid(row=101, column=0, sticky="w"))
        self.root.after(0, lambda: self.restore_progress.set(0))
       
        try:
            # Descriptografar
            self.root.after(0, lambda: self.restore_status.configure(text="🔓 Descriptografando backup..."))
           
            with open(enc_file, 'rb') as f:
                salt = f.read(SALT_SIZE)
                encrypted_data = f.read()
           
            self.root.after(0, lambda: self.restore_progress.set(0.25))
           
            key = derive_key(password, salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
           
            self.root.after(0, lambda: self.restore_progress.set(0.50))
           
            # Extrair
            self.root.after(0, lambda: self.restore_status.configure(text="📂 Extraindo arquivos..."))
           
            folder_name = os.path.splitext(os.path.basename(enc_file))[0] + "_restaurado"
            final_path = os.path.join(restore_dest, folder_name)
           
            if not unzip_data(
                decrypted_data,
                final_path,
                lambda p: self.root.after(0, lambda: self.restore_progress.set(p/100))
            ):
                raise Exception("Falha na extração")
           
            self.root.after(0, lambda: self.restore_progress.set(1.0))
            self.root.after(0, lambda: self.restore_status.configure(
                text="✅ Restauração concluída!",
                text_color=SUCCESS_COLOR
            ))
            self.root.after(0, lambda: messagebox.showinfo(
                "Sucesso!",
                f"Backup restaurado em:\n\n{final_path}"
            ))
           
        except InvalidToken:
            self.root.after(0, lambda: self.restore_status.configure(
                text="❌ Senha incorreta!",
                text_color=ERROR_COLOR
            ))
            self.root.after(0, lambda: messagebox.showerror("Erro", "Senha incorreta ou arquivo corrompido!"))
        except Exception as e:
            self.root.after(0, lambda: self.restore_status.configure(
                text=f"❌ Erro: {str(e)}",
                text_color=ERROR_COLOR
            ))
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao restaurar:\n{str(e)}"))
       
        finally:
            self.root.after(0, lambda: self.restore_btn.configure(state="normal", text="🔓 DESCRIPTOGRAFAR E RESTAURAR"))


# ==============================================================================
# MAIN
# ==============================================================================


if __name__ == "__main__":
    root = ctk.CTk()
    app = ClausumGUI(root)
    root.mainloop()
