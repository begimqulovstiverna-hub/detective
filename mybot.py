import telebot
from telebot import types
import subprocess
import os
import time
import requests
from fpdf import FPDF
from PIL import Image
from PIL.ExifTags import TAGS

# ⚠️ TOKENINGIZNI KIRITING
TOKEN = '8372622031:AAFaKQlDCKcEO0qPDPXASHTisTdyn_O_UgU'
bot = telebot.TeleBot(TOKEN)
SHERLOCK_PATH = "/home/kali/sherlock/sherlock_project/sherlock.py"


# --- METADATA (RASM TAHLILI) - BUNI ENG TEPAGA QO'YING ---
@bot.message_handler(content_types=['document'])
# --- UNIVERSAL FAYL HANDLERI (Metadata + VirusScan) ---
@bot.message_handler(content_types=['document'])
def handle_universal_file(message):
    # 1. AGAR FAYL RASM BO'LSA (Metadata tahlili)
    if message.document.mime_type.startswith('image/'):
        status_msg = bot.send_message(message.chat.id, "🛰 **Sun'iy yo'ldosh tahlili boshlandi...**\n`[▓▓▓░░░░░░░] 30%`", parse_mode='Markdown')
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            temp_name = f"meta_{message.chat.id}.jpg"
            with open(temp_name, 'wb') as f:
                f.write(downloaded_file)
            
            bot.edit_message_text("🔍 **Exif ma'lumotlar o'qilmoqda...**\n`[▓▓▓▓▓▓░░░░] 60%`", message.chat.id, status_msg.message_id, parse_mode='Markdown')

            img = Image.open(temp_name)
            exif_data = img._getexif()
            if exif_data:
                report = "📸 **RASM METADATA HISOBOTI:**\n" + "—" * 20 + "\n"
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    report += f"🔹 **{tag}**: `{value}`\n"
                bot.edit_message_text(report[:4000], message.chat.id, status_msg.message_id, parse_mode='Markdown')
            else:
                bot.edit_message_text("❌ **Metadata topilmadi.**", message.chat.id, status_msg.message_id)
            
            img.close()
            os.remove(temp_name)
        except Exception as e:
            bot.edit_message_text(f"❗ **Xatolik:** `{str(e)}`", message.chat.id, status_msg.message_id, parse_mode='Markdown')

# 2. AGAR FAYL BOSHQA TURDA BO'LSA (Virus Scan - APK, EXE, ZIP...)
    else:
        if message.document.file_size > 32 * 1024 * 1024:
            bot.reply_to(message, "❌ **Xato:** Fayl 32MB dan katta.")
            return

        status_msg = bot.send_message(message.chat.id, "📥 **Fayl VirusTotal serveriga yuklanmoqda...**", parse_mode='HTML')
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            file_name = message.document.file_name
            
            with open(file_name, 'wb') as new_file:
                new_file.write(downloaded_file)

            # 1-QADAM: Faylni yuklash
            url = "https://www.virustotal.com/api/v3/files"
            with open(file_name, "rb") as f:
                files = {"file": (file_name, f)}
                headers = {"x-apikey": VT_API_KEY}
                response = requests.post(url, files=files, headers=headers)
            
            analysis_id = response.json()['data']['id']
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            # 2-QADAM: Tahlil tugashini kutish (Aqlli sikl)
            bot.edit_message_text("🔍 **70+ Antiviruslar tekshirmoqda...**\n`[▓▓▓░░░░░░░] 30%` \n\n<i>Bu jarayon 1 daqiqagacha davom etishi mumkin.</i>", message.chat.id, status_msg.message_id, parse_mode='HTML')
            
            start_time = time.time()
            while True:
                # Har 10 soniyada natijani tekshiramiz
                report_resp = requests.get(report_url, headers=headers).json()
                status = report_resp['data']['attributes']['status']
                
                if status == "completed":
                    break # Tekshiruv tugadi
                
                # Agar 3 daqiqadan oshsa, kutishni to'xtatamiz
                if time.time() - start_time > 180:
                    break
                
                time.sleep(10) # 10 soniya kutib qayta so'raymiz

            # 3-QADAM: Yakuniy natijani chiqarish
            stats = report_resp['data']['attributes']['stats']
            
            # Xavflilik darajasiga qarab rang berish
            if stats['malicious'] > 5:
                res_color = "🔴 JUDA XAVFLI"
            elif stats['malicious'] > 0:
                res_color = "🟠 SHUBHALI"
            else:
                res_color = "🟢 TOZA"

            report_text = (
                f"🛡 <b>Fayl: {file_name}</b>\n"
                f"📊 <b>Natija: {res_color}</b>\n"
                f"{'—' * 20}\n"
                f"🚫 Malicious: <b>{stats['malicious']}</b>\n"
                f"⚠️ Suspicious: <b>{stats['suspicious']}</b>\n"
                f"✅ Undetected: <b>{stats['undetected']}</b>\n\n"
                f"🔗 <a href='https://www.virustotal.com/gui/file-analysis/{analysis_id}'>Batafsil hisobot (Saytda)</a>\n\n"
                f"💡 <i>Eslatma: To'liq tahlil uchun saytga o'ting.</i>"
            )
            
            bot.edit_message_text(report_text, message.chat.id, status_msg.message_id, parse_mode='HTML', disable_web_page_preview=True)
            
            # Faylni serverdan o'chirish
            if os.path.exists(file_name):
                os.remove(file_name)

        except Exception as e:
            print(f"VT Error: {e}")
            bot.edit_message_text(f"❌ **Xato:** Tahlil jarayonida muammo yuz berdi.", message.chat.id, status_msg.message_id)
# Metadata tugmasi bosilganda yo'riqnoma berish
@bot.message_handler(func=lambda message: message.text == '📸 Metadata')
def metadata_instruction(message):
    instruction = (
        "📸 **Metadata tahlil bo'limi**\n\n"
        "Rasm qayerda va qachon olinganini bilish uchun:\n"
        "1. Pastdagi 📎 (skrepka) tugmasini bosing.\n"
        "2. **Fayl (File/Document)** bo'limini tanlang.\n"
        "3. Rasmni tanlang va yuboring.\n\n"
        "⚠️ _Muhim: Oddiy 'Photo' qilib yuborsangiz natija bo'lmaydi!_"
    )
    bot.send_message(message.chat.id, instruction, parse_mode='Markdown')
##############################
#ip 

@bot.message_handler(func=lambda message: message.text == '🌐 IP Tracker')
def ip_handler(message):
    msg = bot.send_message(message.chat.id, "📍 *Global IP manzilni yuboring:* \n(Masalan: `213.230.87.48`)", parse_mode='Markdown')
    bot.register_next_step_handler(msg, track_ip_detailed)

def track_ip_detailed(message):
    ip = message.text.strip()
    # Progress simulyatsiyasi
    status = bot.send_message(message.chat.id, "📡 *Signal yuborilmoqda...* \n`[████░░░░░░] 40%`", parse_mode='Markdown')
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query").json()
        
        if response['status'] == 'success':
            time.sleep(1)
            bot.edit_message_text("🛰 *Sun'iy yo'ldosh ma'lumotlari olindi...* \n`[████████░░] 80%`", message.chat.id, status.message_id, parse_mode='Markdown')
            
            res_text = (
                f"🌐 *IP TAHLILI: {response['query']}*\n\n"
                f"🏳️ **Davlat:** `{response['country']} ({response['countryCode']})`\n"
                f"🏙 **Shahar:** `{response['city']}`\n"
                f"📡 **Provayder:** `{response['isp']}`\n"
                f"⏰ **Vaqt mintaqasi:** `{response['timezone']}`\n"
                f"📍 **Koordinata:** `{response['lat']}, {response['lon']}`\n\n"
                f"🔗 [Xaritada ko'rish](https://www.google.com/maps?q={response['lat']},{response['lon']})"
            )
            bot.send_message(message.chat.id, res_text, parse_mode='Markdown')
        else:
            bot.send_message(message.chat.id, "❌ *Xato:* IP manzil topilmadi yoki noto'g'ri kiritildi.")
            
    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ *Tizim xatosi:* {str(e)}")
    
    finally:
        bot.delete_message(message.chat.id, status.message_id)


###############################
# --- SHERLOCK (USERNAME QIDIRUV) ---
@bot.message_handler(func=lambda message: message.text == '🔍 Sherlock')
def sherlock_handler(message):
    msg = bot.send_message(message.chat.id, "👤 *Username yuboring:* \n(Masalan: `johndoe`)", parse_mode='Markdown')
    bot.register_next_step_handler(msg, run_sherlock_pro)

def run_sherlock_pro(message):
    username = message.text.strip().replace('@', '')
    status = bot.send_message(message.chat.id, f"📡 *{username}* bo'yicha global qidiruv boshlandi...", parse_mode='Markdown')
    
    try:
        # Progress bar
        time.sleep(1)
        bot.edit_message_text(f"🔍 *Bazalar tahlil qilinmoqda...* \n`[██████░░░░] 60%`", message.chat.id, status.message_id, parse_mode='Markdown')
        
        cmd = f"python3 {SHERLOCK_PATH} {username} --timeout 1 --print-found"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8')
        
        # Hisobot yaratish (PDF)
        bot.edit_message_text(f"📄 *Hisobot tayyorlanmoqda...* \n`[█████████░] 90%`", message.chat.id, status.message_id, parse_mode='Markdown')
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"OSINT SHERLOCK REPORT: {username}", ln=1, align='C')
        
        found_links = [line for line in result.split('\n') if "http" in line]
        
        if found_links:
            for link in found_links:
                pdf.multi_cell(0, 10, txt=link)
            
            pdf_file = f"{username}_results.pdf"
            pdf.output(pdf_file)
            
            with open(pdf_file, 'rb') as doc:
                bot.send_document(message.chat.id, doc, caption=f"✅ *{username}* uchun qidiruv yakunlandi.")
            os.remove(pdf_file)
        else:
            bot.send_message(message.chat.id, f"❌ *{username}* bo'yicha hech qanday profil topilmadi.")

    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ *Xato yuz berdi:* Sherlock o'rnatilganligini va yo'l to'g'riligini tekshiring.")
    
    finally:
        bot.delete_message(message.chat.id, status.message_id)

# --- DEEP SEARCH (GOOGLE DORKING) ---
@bot.message_handler(func=lambda message: message.text == '🔎 Deep Search')
def deep_search_handler(message):
    msg = bot.send_message(message.chat.id, "👤 *Ism-familiya kiriting:*", parse_mode='Markdown')
    bot.register_next_step_handler(msg, run_google_dorks)

def run_google_dorks(message):
    query = message.text.strip()
    
    # Google qidiruv so'rovlarini tayyorlash (Dorks)
    # Bu yerda har bir link [Matn](URL) formatida bo'lishi shart
    pdf_link = f"https://www.google.com/search?q=%22{query}%22+filetype:pdf"
    social_link = f"https://www.google.com/search?q=%22{query}%22+site:instagram.com+OR+site:facebook.com+OR+site:linkedin.com"
    archive_link = f"https://www.google.com/search?q=%22{query}%22+-inurl:htm+-inurl:html"
    general_link = f"https://www.google.com/search?q=%22{query}%22"

    status = bot.send_message(message.chat.id, f"🔍 **{query}** tahlil qilinmoqda...", parse_mode='Markdown')

    # Markdown formatida linklarni yig'amiz
    res_text = (
        f"🕵️‍♂️ **{query}** bo'yicha chuqur qidiruv linklari:\n\n"
        f"🔗 [Hujjatlar va PDFlar]({pdf_link})\n"
        f"🔗 [Ijtimoiy tarmoqlar]({social_link})\n"
        f"🔗 [Eski arxivlar]({archive_link})\n"
        f"🌍 [Umumiy qidiruv natijalari]({general_link})\n\n"
        "💡 _Ko'k rangli yozuvlar ustiga bossangiz, Google natijalari ochiladi._"
    )

    time.sleep(1) # Ozgina kutish vizual effekt beradi
    bot.edit_message_text(res_text, message.chat.id, status.message_id, 
                          parse_mode='Markdown', disable_web_page_preview=True)

##################################
# --- EMAIL TAHLIL (PROFESSIONAL OSINT) ---
@bot.message_handler(func=lambda message: message.text == '📧 Email Tahlil')
def email_start_handler(message):
    msg = bot.send_message(message.chat.id, "📧 **Tahlil qilinadigan email manzilini yuboring:**", parse_mode='Markdown')
    bot.register_next_step_handler(msg, email_advanced_scan)

def email_advanced_scan(message):
    email = message.text.strip().lower()
    
    # Email formatini tekshirish (oddiy filter)
    if "@" not in email or "." not in email:
        bot.send_message(message.chat.id, "❌ **Xato:** Iltimos, to'g'ri email manzilini kiriting (masalan: `user@mail.com`)", parse_mode='Markdown')
        return

    status = bot.send_message(message.chat.id, f"🔎 **{email}** bo'yicha chuqur qidiruv boshlandi...\n`[▓▓▓░░░░░░░] 30%`", parse_mode='Markdown')
    
    # OSINT Linklari (Har bir link bosilganda emailni avtomatik qidiradi)
    # 1. Epieos - Google akkaunt va ijtimoiy tarmoqlarni topish uchun eng zo'ri
    epieos = f"https://epieos.com/?q={email}"
    # 2. Have I Been Pwned - Parol va ma'lumotlar o'g'irlanganini tekshirish
    hibp = f"https://haveibeenpwned.com/account/{email}"
    # 3. IntelligenceX - Arxivlangan ma'lumotlar uchun
    intelx = f"https://intelx.io/?s={email}"
    # 4. Google Dorks - Email qatnashgan ochiq hujjatlarni qidirish
    dork = f"https://www.google.com/search?q=%22{email}%22"

    time.sleep(1)
    bot.edit_message_text(f"🛰 **Raqamli izlar yig'ilmoqda...**\n`[▓▓▓▓▓▓▓░░░] 70%`", message.chat.id, status.message_id, parse_mode='Markdown')

    res_text = (
        f"📧 **EMAIL TAHLIL HISOBOTI: {email}**\n"
        f"{'—' * 22}\n\n"
        f"👤 **Ijtimoiy tarmoqlar va Profil:**\n"
        f"🔗 [Epieos orqali tekshirish]({epieos}) — _Google, Skype, LinkedIn va h.k._\n\n"
        f"🔐 **Xavfsizlik va Sizib chiqishlar:**\n"
        f"🔗 [Hukerlar bazasini tekshirish]({hibp})\n"
        f"🔗 [Arxivlangan ma'lumotlar]({intelx})\n\n"
        f"🌍 **Ochiq tarmoqdagi izlar:**\n"
        f"🔗 [Google Search (Direct)]({dork})\n\n"
        f"{'—' * 22}\n"
        f"💡 **Maslahat:** Linklarning barchasini ko'zdan kechirib chiqing, har biri turli xil bazalardan ma'lumot beradi."
    )

    time.sleep(1)
    bot.edit_message_text(res_text, message.chat.id, status.message_id, 
                          parse_mode='Markdown', disable_web_page_preview=True)


#################################
# --- AVTO-RAQAM HUDUDINI ANIQLASH ---
@bot.message_handler(func=lambda message: message.text == '🚗 Avto-Raqam')
def car_start(message):
    msg = bot.send_message(message.chat.id, "🚘 **Mashina raqamini yuboring:**\n(Masalan: `01 A 123 AA` yoki shunchaki `01`)", parse_mode='Markdown')
    bot.register_next_step_handler(msg, analyze_car_number)

def analyze_car_number(message):
    text = message.text.strip().upper()
    
    # Raqam ichidan faqat raqamlarni ajratib olish (hududni bilish uchun boshidagi 2 ta son kerak)
    clean_num = "".join(filter(str.isdigit, text))
    region_code = clean_num[:2]
    
    # O'zbekiston viloyat kodlari bazasi
    uzb_regions = {
        "01": "Toshkent shahri",
        "10": "Toshkent viloyati",
        "20": "Sirdaryo viloyati",
        "25": "Jizzax viloyati",
        "30": "Samarqand viloyati",
        "40": "Farg'ona viloyati",
        "50": "Namangan viloyati",
        "60": "Andijon viloyati",
        "70": "Qashqadaryo viloyati",
        "75": "Surxondaryo viloyati",
        "80": "Buxoro viloyati",
        "85": "Navoiy viloyati",
        "90": "Xorazm viloyati",
        "95": "Qoraqalpog'iston Respublikasi"
    }

    if region_code in uzb_regions:
        region_name = uzb_regions[region_code]
        res = (
            f"🚗 **RAQAM TAHLILI:** `{text}`\n"
            f"{'—' * 20}\n"
            f"📍 **Hudud:** `{region_name}`\n"
            f"🔢 **Viloyat kodi:** `{region_code}`\n\n"
            f"💡 _Bu raqam ushbu viloyatda ro'yxatdan o'tganligini bildiradi._"
        )
        bot.send_message(message.chat.id, res, parse_mode='Markdown')
    else:
        bot.send_message(message.chat.id, "❌ **Noma'lum hudud.** \nIltimos, O'zbekiston davlat raqamini to'g'ri formatda kiriting (masalan: `01`, `10`, `30`).", parse_mode='Markdown')




##################################
# --- PHONEINFOGA (TELEFON RAQAM TAHLILI) ---
@bot.message_handler(func=lambda message: message.text == '📞 PhoneInfoga')
def phone_start_handler(message):
    msg = bot.send_message(message.chat.id, "📞 **Xalqaro formatdagi telefon raqamini yuboring:**\n(Masalan: `998901234567`)", parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_phone_info)

def process_phone_info(message):
    num = "".join(filter(str.isdigit, message.text)) # Faqat raqamlarni ajratib olish
    
    if len(num) < 9:
        bot.send_message(message.chat.id, "❌ **Xato:** Raqam juda qisqa. Iltimos, to'liq raqamni kiriting.")
        return

    status = bot.send_message(message.chat.id, f"📡 **+{num}** bo'yicha global qidiruv linklari tayyorlanmoqda...", parse_mode='Markdown')

    # PhoneInfoga o'rniga barqaror OSINT linklari
    # 1. IntelX - Telefon raqami bo'yicha sizib chiqqan ma'lumotlarni qidiradi
    intelx_phone = f"https://intelx.io/?s={num}"
    # 2. FreeCarrierLookup - Raqam qaysi kompaniyaga tegishli ekanligini aniq aytadi
    carrier_link = f"https://freecarrierlookup.com/"
    # 3. Truecaller - Ismini bilish uchun eng yaxshisi
    truecaller = f"https://www.truecaller.com/search/uz/{num}"
    # 4. Epieos - Raqamga bog'langan Google akkauntlarni topish
    epieos_phone = f"https://epieos.com/?q={num}&t=phone"

    res_text = (
        f"📞 **RAQAM TAHLILI: +{num}**\n"
        f"{'—' * 22}\n\n"
        f"🔎 **Shaxsni aniqlash (Social OSINT):**\n"
        f"🔗 [Truecaller Web]({truecaller}) — _Ismini ko'rish_\n"
        f"🔗 [Epieos Phone]({epieos_phone}) — _Google/Skype tahlil_\n\n"
        f"🔐 **Ma'lumotlar sizib chiqishi (Leaks):**\n"
        f"🔗 [IntelX Search]({intelx_phone}) — _Parol va bazalar_\n\n"
        f"📡 **Texnik ma'lumotlar:**\n"
        f"🔗 [Carrier Lookup]({carrier_link}) — _Operatorni aniqlash_\n\n"
        f"{'—' * 22}\n"
        f"💡 **Maslahat:** Har bir link turli xil bazalarni tekshiradi. To'liq ma'lumot olish uchun hammasini ko'rib chiqing."
    )

    time.sleep(1)
    bot.edit_message_text(res_text, message.chat.id, status.message_id, parse_mode='Markdown', disable_web_page_preview=True)
#####################################
# --- FACE SEARCH (YUZ ORQALI QIDIRUV) ---
@bot.message_handler(func=lambda message: message.text == '👤 Face Search')
def face_search_handler(message):
    msg = bot.send_message(message.chat.id, "👤 **Qidirilayotgan shaxsning rasmini yuboring:**\n(Rasmda yuz aniq ko'ringan bo'lishi kerak)", parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_face_search)

def process_face_search(message):
    if message.content_type == 'photo' or (message.content_type == 'document' and message.document.mime_type.startswith('image/')):
        status = bot.send_message(message.chat.id, "⚙️ **Tasvir tahlil qilinmoqda...**\n`[▓▓▓▓░░░░░░] 40%`", parse_mode='Markdown')
        
        # Bu yerda biz yuz qidiruvchi gigant servislarga yo'naltiramiz
        # Chunki shaxsiy serverda millionlab yuzlar bazasini saqlash imkonsiz
        res_text = (
            "👤 **Yuz bo'yicha qidiruv tizimi tayyor!**\n\n"
            "Telegram ichida to'liq yuz qidiruvi cheklangan, shuning uchun quyidagi eng kuchli OSINT vositalaridan foydalaning:\n\n"
            "1️⃣ **[PimEyes](https://pimeyes.com/en)** — Dunyodagi eng aniq qidiruv tizimi. Rasmni yuklang va u internetdagi barcha nusxalarni topadi.\n"
            "2️⃣ **[Yandex Images](https://yandex.com/images/search?rpt=imageview)** — Rossiya va MDH davlatlari (Instagram/VK) uchun eng yaxshisi.\n"
            "3️⃣ **[Search4Faces](https://search4faces.com/)** — Ijtimoiy tarmoqlardagi profillarni topish uchun maxsus servis.\n"
            "4️⃣ **[FaceCheck.ID](https://facecheck.id/)** — Internetdagi jinoyatchilar va ochiq profillar bazasi.\n\n"
            "💡 **Maslahat:** Yandex Images-ga o'tib, 'Select file' tugmasini bosing va ushbu rasmni yuklang."
        )
        
        time.sleep(1)
        bot.edit_message_text(res_text, message.chat.id, status.message_id, parse_mode='Markdown', disable_web_page_preview=False)
    else:
        bot.send_message(message.chat.id, "❌ **Xato:** Iltimos, faqat rasm yuboring!")

####################################
# --- ID FINDER (USERNAME ORQALI ID TOPISH) ---
# --- ID FINDER (USERNAME ORQALI ID TOPISH) ---
####################################
# --- ID FINDER (USERNAME ORQALI ID TOPISH) ---
@bot.message_handler(func=lambda message: message.text == '🆔 ID Finder')
def id_finder_start(message):
    instruction = (
        "🆔 <b>ID aniqlash bo'limi</b>\n\n"
        "Foydalanuvchi ID-sini bilish uchun:\n"
        "1. Uning <b>username</b>ini yozing (masalan: <code>@durov</code>).\n"
        "2. Yoki uning xabarini ushbu botga <b>forward</b> qiling.\n\n"
        "📝 <i>Hozir usernameni yuboring:</i>"
    )
    # register_next_step_handler qo'shildi - endi bot keyingi xabarni kutadi
    msg = bot.send_message(message.chat.id, instruction, parse_mode='HTML')
    bot.register_next_step_handler(msg, get_user_id)

def get_user_id(message):
    # Agar foydalanuvchi forward yuborgan bo'lsa (next_step ichida ham tekshiramiz)
    if message.forward_from or message.forward_from_chat:
        handle_forward(message)
        return

    text = message.text.strip()
    
    # Agar foydalanuvchi "me" yoki o'z usernamini yozsa
    if text.lower() == 'me' or (message.from_user.username and text.replace('@', '') == message.from_user.username):
        user = message.from_user
        res_text = (
            f"🆔 <b>SIZNING MA'LUMOTLARINGIZ:</b>\n"
            f"{'—' * 22}\n"
            f"👤 <b>Nomi:</b> {user.first_name}\n"
            f"🆔 <b>ID:</b> <code>{user.id}</code>\n"
            f"🏷 <b>Username:</b> @{user.username if user.username else 'Yoq'}\n"
            f"{'—' * 22}"
        )
        bot.send_message(message.chat.id, res_text, parse_mode='HTML')
        return

    # Boshqa foydalanuvchilar uchun qidiruv
    username = text.replace('@', '')
    status = bot.send_message(message.chat.id, f"🔍 <b>@{username}</b> qidirilmoqda...", parse_mode='HTML')
    
    try:
        # Telegram Bot API cheklovi: Bot foydalanuvchini avval ko'rgan bo'lishi shart
        chat = bot.get_chat('@' + username)
        res_text = (
            f"🆔 <b>TOPILGAN MA'LUMOT:</b>\n"
            f"{'—' * 22}\n"
            f"👤 <b>Nomi:</b> {chat.first_name if chat.first_name else ''}\n"
            f"🆔 <b>ID:</b> <code>{chat.id}</code>\n"
            f"🏷 <b>Username:</b> @{username}\n"
            f"{'—' * 22}"
        )
        bot.edit_message_text(res_text, message.chat.id, status.message_id, parse_mode='HTML')
    except Exception:
        bot.edit_message_text(
            f"❌ <b>Xato: chat not found</b>\n\n"
            f"Bot <b>@{username}</b> ni topa olmadi.\n\n"
            f"💡 <b>Nima qilish kerak?</b>\n"
            f"Ushbu foydalanuvchi botga <code>/start</code> bosmagan. ID-ni olish uchun uning xabarini ushbu botga <b>forward</b> qilib ko'ring.",
            message.chat.id, status.message_id, parse_mode='HTML'
        )
#################################
# --- FORWARD XABAR ORQALI ID TOPISH ---
@bot.message_handler(func=lambda message: message.forward_from or message.forward_from_chat)
def handle_forward(message):
    if message.forward_from:
        user = message.forward_from
        res = (
            f"🆔 <b>FORWARD TAHLILI:</b>\n"
            f"{'—' * 22}\n"
            f"👤 <b>Nomi:</b> {user.first_name}\n"
            f"🆔 <b>ID:</b> <code>{user.id}</code>\n"
            f"🏷 <b>Username:</b> @{user.username if user.username else 'Yoq'}\n"
            f"🤖 <b>Botmi:</b> {'Ha' if user.is_bot else 'Yoq'}\n"
            f"{'—' * 22}"
        )
    elif message.forward_from_chat:
        chat = message.forward_from_chat
        res = (
            f"📢 <b>KANAL/GURUH ID-SI:</b>\n"
            f"{'—' * 22}\n"
            f"🏷 <b>Nomi:</b> {chat.title}\n"
            f"🆔 <b>ID:</b> <code>{chat.id}</code>\n"
            f"👤 <b>Turi:</b> {chat.type}\n"
            f"{'—' * 22}"
        )
    bot.send_message(message.chat.id, res, parse_mode='HTML')
################################
# --- ISMLAR TARIXI (NICKNAME HISTORY) ---
@bot.message_handler(func=lambda message: message.text == '📜 Ismlar Tarixi')
def name_history_start(message):
    msg = bot.send_message(message.chat.id, "📜 <b>Ismlar tarixini bilish uchun:</b>\nFoydalanuvchi ID-sini yuboring yoki xabarini forward qiling:", parse_mode='HTML')
    bot.register_next_step_handler(msg, process_name_history)

def process_name_history(message):
    user_id = "".join(filter(str.isdigit, message.text)) if not message.forward_from else message.forward_from.id
    if user_id:
        link = f"https://t.me/SangMataInfo_bot?start={user_id}"
        bot.send_message(message.chat.id, f"✅ <b>ID olingan:</b> <code>{user_id}</code>\n\nUshbu foydalanuvchining oldingi ismlari va usernamelarini ko'rish uchun pastdagi tugmani bosing:\n\n🔗 <a href='{link}'>Tarixni ko'rish (SangMata)</a>", parse_mode='HTML')
    else:
        bot.send_message(message.chat.id, "❌ Noto'g'ri ID yoki xabar.")

# --- QO'SHILGAN SANA (CREATION DATE) ---
@bot.message_handler(func=lambda message: message.text == '📅 Qo\'shilgan Sana')
def creation_date_start(message):
    msg = bot.send_message(message.chat.id, "📅 <b>Telegramga qo'shilgan vaqtini aniqlash:</b>\nID yuboring yoki xabarini forward qiling:", parse_mode='HTML')
    bot.register_next_step_handler(msg, process_creation_date)

def process_name_history(message):
    # ID ni ajratib olish
    user_id = "".join(filter(str.isdigit, message.text)) if not message.forward_from else message.forward_from.id
    
    if user_id:
        # Alternativ botlar ro'yxati
        sangmata = f"https://t.me/SangMataInfo_bot?start={user_id}"
        telesint = f"https://t.me/telesint_bot?start={user_id}"
        usinfobot = f"https://t.me/usinfobot?start={user_id}"

        res_text = (
            f"🕵️‍♂️ <b>ISMLAR TARIXI TAHLILI</b>\n"
            f"🆔 <b>Maqsadli ID:</b> <code>{user_id}</code>\n"
            f"{'—' * 22}\n\n"
            f"Agar bitta bot javob bermasa, keyingisidan foydalaning:\n\n"
            f"1️⃣ <b>SangMata (Asosiy):</b>\n"
            f"🔗 <a href='{sangmata}'>Tarixni ko'rish</a>\n\n"
            f"2️⃣ <b>TeleSint (Muqobil):</b>\n"
            f"🔗 <a href='{telesint}'>Guruhlar tarixini ko'rish</a>\n\n"
            f"3️⃣ <b>uSinfo (Zaxira):</b>\n"
            f"🔗 <a href='{usinfobot}'>Profil tahlili</a>\n\n"
            f"{'—' * 22}\n"
            f"💡 <b>Yo'riqnoma:</b> Linkni bosing, botga o'ting va <b>START</b> tugmasini bosing."
        )
        bot.send_message(message.chat.id, res_text, parse_mode='HTML', disable_web_page_preview=True)
    else:
        bot.send_message(message.chat.id, "❌ <b>Xato:</b> ID aniqlanmadi. Iltimos, raqam ko'rinishidagi ID yuboring.")
# --- STORIES DOWNLOADER (YANGILANGAN) ---
@bot.message_handler(func=lambda message: message.text == '📱 Stories Downloader')
def stories_start(message):
    res = (
        "📱 <b>Telegram Hikoyalarni (Stories) Yuklash</b>\n\n"
        "Hozirda botlar orqali yuklash cheklangan. Quyidagi servislar orqali anonim va bepul yuklab olishingiz mumkin:\n\n"
        "1️⃣ <b>Telegram Web (Z-version)</b> — Kompyuterda brauzer orqali kirib, hikoyani ochib, o'ng tugmani bosib 'Save video as...' qilib yuklash mumkin.\n\n"
        "2️⃣ <b>SaveTG Bot API</b> — Agar foydalanuvchi kanalda hikoya qoldirgan bo'lsa, @SaveTG_Bot orqali urinib ko'ring.\n\n"
        "3️⃣ <b>Insta-Style Web Viewers:</b>\n"
        "Hozirda eng ishonchli usul — hikoya linkini nusxalab, ushbu saytga tashlash:\n"
        "🔗 <a href='https://telemetr.io/'>Telemetr.io</a> (Kanal hikoyalari uchun)\n\n"
        "⚠️ <b>Muhim:</b> Agar foydalanuvchi hikoyasini 'Faqat kontaktlarim uchun' (Contacts Only) qilib qo'ygan bo'lsa, uni hech qanday bot yoki servis yuklay olmaydi. Faqat 'Hamma uchun' (Public) bo'lgan hikoyalarni ko'rish mumkin."
    )
    bot.send_message(message.chat.id, res, parse_mode='HTML', disable_web_page_preview=True)


#################################
# --- VIRUSTOTAL INTEGRATSIYASI ---
VT_API_KEY = "6b95773b917ad73a1e4714aef7d1381673cb0246572ccd7da7411d7b4d45faa5" # API kalitingizni shu yerga yozing

@bot.message_handler(func=lambda message: message.text == '🛡 Virus Scan')
def virus_scan_start(message):
    instruction = (
        "🛡 <b>VirusTotal Scan bo'limi</b>\n\n"
        "Shubhali fayllarni (APK, EXE, ZIP, va h.k.) yuboring.\n"
        "Bot ularni 70+ antiviruslar bazasida tahlil qiladi.\n\n"
        "⚠️ <i>Maksimal hajm: 32 MB</i>"
    )
    bot.send_message(message.chat.id, instruction, parse_mode='HTML')





##################################
# --- ASOSIY MENYU VA START ---
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    btn1 = types.KeyboardButton('🔍 Sherlock')
    btn2 = types.KeyboardButton('📸 Metadata')
    btn3 = types.KeyboardButton('🌐 IP Tracker')
    btn4 = types.KeyboardButton('🔎 Deep Search')
    btn5 = types.KeyboardButton('📧 Email Tahlil')
    btn6 = types.KeyboardButton('🚗 Avto-Raqam')
    btn7 = types.KeyboardButton('❓ Yordam')
    btn8 = types.KeyboardButton('👤 Face Search') # Yangi tugma
    btn9 = types.KeyboardButton('📞 PhoneInfoga')
    btn10 = types.KeyboardButton('🆔 ID Finder') # Yangi tugma
    btn11 = types.KeyboardButton('📜 Ismlar Tarixi') 
    btn12 = types.KeyboardButton('📅 Qo\'shilgan Sana')
    btn13 = types.KeyboardButton('📱 Stories Downloader')
    btn14 = types.KeyboardButton('🛡 Virus Scan')
    
    markup.add(btn1, btn2, btn3, btn4, btn5, btn6, btn7, btn8, btn9, btn10, btn11, btn12, btn13, btn14)
    
    bot.send_message(message.chat.id, "🕵️ *OSINT Pro-Bot v4.0*\n\nKerakli bo'limni tanlang:", 
                     parse_mode='Markdown', reply_markup=markup)

@bot.message_handler(func=lambda message: message.text == '❓ Yordam')
def help_cmd(message):
    help_text = (
        "📖 *Qisqa qo'llanma:*\n\n"
        "1. **Sherlock**: Username orqali qidiradi.\n"
        "2. **Metadata**: Rasmni 'Fayl' qilib tashlang.\n"
        "3. **IP Tracker**: Global IP manzillar uchun.\n"
        "4. **Deep Search**: Google dorking usuli."
    )
    bot.send_message(message.chat.id, help_text, parse_mode='Markdown')

# BOTNI ISHGA TUSHIRISH (Xatoliklarga chidamli variant)
if __name__ == "__main__":
    print("🚀 Bot ishga tushdi...")
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            print(f"⚠️ Polling xatosi: {e}")
            time.sleep(5) # 5 soniya kutib qayta ulanadi
