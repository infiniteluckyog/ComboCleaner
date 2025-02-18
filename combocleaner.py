import re
import os
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple
import itertools
from functools import lru_cache
import xxhash
import time
from datetime import datetime

# ULTIMATE OPTIMIZATION SETTINGS
MAX_WORKERS = 32
CHUNK_SIZE = 1024 * 1024 * 20
BUFFER_SIZE = 1024 * 1024 * 32
MAX_BATCH_SIZE = 1000000

# Optimized regex patterns
EMAIL_PASS_PATTERN = re.compile(
    b'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+):([^:\\s\\r\\n]+)',
    re.MULTILINE | re.DOTALL | re.ASCII
)

CARD_PATTERN = re.compile(
    b'''(?:^|[^0-9])([45][0-9]{15}|4[0-9]{12}(?:[0-9]{3})?|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})[^0-9]*?([0-9]{2})[^0-9]*?([0-9]{2,4})[^0-9]*?([0-9]{3,4})''',
    re.MULTILINE | re.DOTALL | re.ASCII
)

# Initialize thread pool
thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

@lru_cache(maxsize=4096)
def cached_decode(byte_string):
    return byte_string.decode('ascii', errors='ignore')

def process_chunk(chunk: bytes) -> List[Tuple[str, str]]:
    try:
        matches = EMAIL_PASS_PATTERN.finditer(chunk)
        return [(cached_decode(m.group(1)), cached_decode(m.group(2)))
                for m in matches]
    except:
        return []

def process_card_chunk(chunk: bytes) -> List[Tuple[str, str, str, str]]:
    try:
        results = []
        matches = CARD_PATTERN.finditer(chunk)
        
        for m in matches:
            card = cached_decode(m.group(1))
            if not card or len(card) < 15:
                continue
                
            # Quick Luhn check using bitwise operations
            s1 = sum(int(d) for d in card[-1::-2])
            s2 = sum(sum(divmod(int(d)*2,10)) for d in card[-2::-2])
            if (s1 + s2) % 10 != 0:
                continue

            month = cached_decode(m.group(2))
            year = cached_decode(m.group(3))
            cvv = cached_decode(m.group(4))

            # Quick month/year validation
            if not (1 <= int(month) <= 12):
                continue
                
            year = year[-2:] if len(year) == 4 else year
            results.append((card, month, year, cvv))
            
        return results
    except:
        return []

async def update_progress(message, start_time):
    try:
        while True:
            elapsed = time.time() - start_time
            progress_text = (
                f"⚡ 𝗦𝘂𝗰𝗰𝗲𝘀𝘀...\n"
                f"⏱️ 𝗧𝗶𝗺𝗲: {elapsed:.1f}s"
            )
            await message.edit_text(progress_text)
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"Progress update error: {e}")
async def extract_combos(content: bytes) -> List[Tuple[str, str]]:
    chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
    
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        chunk_results = await loop.run_in_executor(
            None,
            lambda: list(itertools.chain.from_iterable(
                executor.map(process_chunk, chunks, chunksize=max(1, len(chunks)//MAX_WORKERS))
            ))
        )
    
    seen = set()
    return [combo for combo in chunk_results if combo[0] not in seen and not seen.add(combo[0])]

async def extract_cards(content: bytes) -> List[Tuple[str, str, str, str]]:
    chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
    
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        card_results = await loop.run_in_executor(
            None,
            lambda: list(itertools.chain.from_iterable(
                executor.map(process_card_chunk, chunks, chunksize=max(1, len(chunks)//MAX_WORKERS))
            ))
        )
    
    seen = set()
    return [card for card in card_results if card[0] not in seen and not seen.add(card[0])]

async def save_combos(combos: List[Tuple[str, str]], filename: str):
    with open(filename, 'wb', buffering=BUFFER_SIZE) as f:
        batch_size = 10000
        for i in range(0, len(combos), batch_size):
            batch = combos[i:i + batch_size]
            f.write(b''.join(
                f"{email}:{password}\n".encode('utf-8')
                for email, password in batch
            ))

async def save_cards(cards: List[Tuple[str, str, str, str]], filename: str):
    with open(filename, 'wb', buffering=BUFFER_SIZE) as f:
        batch_size = 10000
        for i in range(0, len(cards), batch_size):
            batch = cards[i:i + batch_size]
            f.write(b''.join(
                f"{card}|{month}|{year}|{cvv}\n".encode('utf-8')
                for card, month, year, cvv in batch
            ))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = await update.message.reply_text("🟢 𝗔𝗹𝗶𝘃𝗲")
    
    animations = [
        ("𝗕𝗼𝘁 𝗠𝗮𝗱𝗲 𝗕𝘆  @Kiltes", 0.1),
        ("𝗝𝗼𝗶𝗻 @Newlester 𝗙𝗼𝗿 𝗠𝗼𝗿𝗲 𝗙𝗿𝗲𝗲 𝗕𝗼𝘁𝘀", 0.2),
        ("🤖", 0.3),
        ("\n🤖 𝗪𝗲𝗹𝗰𝗼𝗺𝗲 𝗧𝗼 𝗖𝗼𝗺𝗯𝗼 𝗖𝗹𝗲𝗮𝗻𝗲𝗿 𝗕𝗼𝘁!\n\n"
         "━━━━━━━━━━━━━━━━━━\n"
         "🗂️ Send /clean As A Reply To A Combo File To Clean It\n"
         "━━━━━━━━━━━━━━━━━━\n"
         "💳 Send /cards As A Reply To Clean Card Combos\n"
         "━━━━━━━━━━━━━━━━━━\n"
         "🧾 Send /txt As A Reply To Convert Text To A .txt File\n"
         "━━━━━━━━━━━━━━━━━━\n"
         "🪚 Send /split {amount} To Any Txt File To Split\n"
         "━━━━━━━━━━━━━━━━━━", 0.4)
    ]
    
    for animation_text, delay in animations:
        await asyncio.sleep(delay)
        await message.edit_text(animation_text)

async def clean(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❗ Reply to a file")
        return

    try:
        start_time = time.time()
        status = await update.message.reply_text("⚡ 𝗣𝗿𝗼𝗰𝗲𝘀𝘀𝗶𝗻𝗴...")
        
        doc = update.message.reply_to_message.document
        file = await doc.get_file()
        content = await file.download_as_bytearray()
        
        progress_task = asyncio.create_task(update_progress(status, start_time))
        
        combos = await extract_combos(content)
        total_combos = len(combos)
        
        progress_task.cancel()
        
        if not total_combos:
            await status.edit_text("❌ No combos found!")
            return
        
        elapsed_time = time.time() - start_time
        await status.edit_text(
            f"🔍 𝗙𝗼𝘂𝗻𝗱 {total_combos:,} 𝗟𝗶𝗻𝗲𝘀...\n"
            f"⏱️ 𝗧𝗶𝗺𝗲 𝗧𝗮𝗸𝗲𝗻: {elapsed_time:.2f} seconds"
        )
        
        batch_size = min(MAX_BATCH_SIZE, max(250000, total_combos // 3))
        upload_tasks = []
        
        for i in range(0, total_combos, batch_size):
            batch = combos[i:i + batch_size]
            batch_num = i // batch_size + 1
            filename = f"cleaned_{batch_num}.txt"
            
            await save_combos(batch, filename)
            
            with open(filename, "rb") as f:
                upload_tasks.append(
                    update.message.reply_document(
                        document=InputFile(f),
                        caption=f"✅ 𝗕𝗮𝘁𝗰𝗵 {batch_num} | {len(batch):,} 𝗟𝗶𝗻𝗲𝘀"
                    )
                )
            os.remove(filename)
        
        if upload_tasks:
            await asyncio.gather(*upload_tasks)
        
        final_time = time.time() - start_time
        speed = total_combos/final_time
        await status.edit_text(
            f"✅ 𝗖𝗹𝗲𝗮𝗻𝗶𝗻𝗴 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲!\n"
            f"📊 𝗧𝗼𝘁𝗮𝗹 𝗟𝗶𝗻𝗲𝘀: {total_combos:,}\n"
            f"⏱️ 𝗧𝗼𝘁𝗮𝗹 𝗧𝗶𝗺𝗲: {final_time:.2f} seconds\n"
            f"⚡ 𝗦𝗽𝗲𝗲𝗱: {speed:.2f} Line/second\n"
            f"🚀 𝗨𝘀𝗮𝗴𝗲: {speed*60:.0f} Line/minute"
        )
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def cards(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❗ Reply to a file containing card information")
        return
    
    try:
        start_time = time.time()
        status = await update.message.reply_text("⚡ Processing")
        
        doc = update.message.reply_to_message.document
        file = await doc.get_file()
        content = await file.download_as_bytearray()
        
        progress_task = asyncio.create_task(update_progress(status, start_time))
        
        cards = await extract_cards(content)
        total_cards = len(cards)
        
        progress_task.cancel()
        
        if not total_cards:
            await status.edit_text("❌ No valid cards found!")
            return
            
        elapsed_time = time.time() - start_time
        await status.edit_text(
            f"🔍 Found {total_cards:,} valid cards...\n"
            f"⏱️ Time taken: {elapsed_time:.2f} seconds"
        )
        
        batch_size = min(MAX_BATCH_SIZE, max(250000, total_cards // 3))
        upload_tasks = []
        
        for i in range(0, total_cards, batch_size):
            batch = cards[i:i + batch_size]
            batch_num = i // batch_size + 1
            filename = f"cards_{batch_num}.txt"
            
            await save_cards(batch, filename)
            
            with open(filename, "rb") as f:
                upload_tasks.append(
                    update.message.reply_document(
                        document=InputFile(f),
                        caption=f"✅ 𝗕𝗮𝘁𝗰𝗵 {batch_num} | {len(batch):,} 𝗖𝗮𝗿𝗱𝘀"
                    )
                )
            os.remove(filename)
        
        if upload_tasks:
            await asyncio.gather(*upload_tasks)
        
        final_time = time.time() - start_time
        speed = total_cards/final_time
        await status.edit_text(
            f"✅ 𝗖𝗮𝗿𝗱𝘀 𝗖𝗹𝗲𝗮𝗻𝗶𝗻𝗴 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲!\n"
            f"📊 𝗧𝗼𝘁𝗮𝗹 𝗖𝗮𝗿𝗱𝘀: {total_cards:,}\n"
            f"⏱️ 𝗧𝗼𝘁𝗮𝗹 𝗧𝗶𝗺𝗲: {final_time:.2f} seconds\n"
            f"⚡ 𝗦𝗽𝗲𝗲𝗱: {speed:.2f} cards/second\n"
            f"🚀 𝗨𝘀𝗮𝗴𝗲: {speed*60:.0f} cards/minute"
        )
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.text:
        await update.message.reply_text("❗ Please reply to a message with /txt")
        return

    try:
        status_msg = await update.message.reply_text("📝 Converting...")
        text_content = update.message.reply_to_message.text
        output_filename = "converted_text.txt"

        with open(output_filename, "w", encoding="utf-8", buffering=BUFFER_SIZE) as file:
            file.write(text_content)

        with open(output_filename, "rb") as output_file:
            await update.message.reply_document(
                document=InputFile(output_file, filename=output_filename),
                caption="✅ Converted to text file"
            )
        os.remove(output_filename)
        await status_msg.delete()
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def split(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❗ Please reply to a text file with /split <number_of_parts>")
        return

    try:
        if not context.args:
            await update.message.reply_text("❗ Please specify number of parts (2-10)\nExample: /split 5")
            return

        num_parts = int(context.args[0])
        if not 2 <= num_parts <= 10:
            await update.message.reply_text("❗ Number of parts must be between 2 and 10")
            return

        status_msg = await update.message.reply_text("📂 Processing file...")
        document = update.message.reply_to_message.document
        file = await document.get_file()
        
        file_content = await file.download_as_bytearray()
        text = file_content.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        total_lines = len(lines)

        if total_lines < num_parts:
            await update.message.reply_text(f"❌ File has fewer lines ({total_lines}) than requested parts ({num_parts})")
            return

        lines_per_part = total_lines // num_parts
        remaining_lines = total_lines % num_parts

        await status_msg.edit_text(f"✂️ Splitting file into {num_parts} parts...")

        split_tasks = []
        start_idx = 0

        for i in range(num_parts):
            current_part_lines = lines_per_part + (1 if i < remaining_lines else 0)
            end_idx = start_idx + current_part_lines
            part_content = "\n".join(lines[start_idx:end_idx])
            
            part_filename = f"part_{i+1}_of_{num_parts}.txt"
            
            with open(part_filename, "w", encoding="utf-8", buffering=BUFFER_SIZE) as f:
                f.write(part_content)

            with open(part_filename, "rb") as f:
                split_tasks.append(
                    update.message.reply_document(
                        document=InputFile(f, filename=part_filename),
                        caption=f"Part {i+1} of {num_parts} | Lines: {current_part_lines:,}"
                    )
                )
            
            os.remove(part_filename)
            start_idx = end_idx

        await asyncio.gather(*split_tasks)
        await status_msg.edit_text(f"✅ Split complete!\nTotal lines: {total_lines:,}\nParts: {num_parts}")

    except ValueError:
        await update.message.reply_text("❗ Please provide a valid number")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

def main():
    bot_token = "8036199885:AAFzdSu8pbCAqlXvkxXMzEeDk9akG481a9I"
    
    app = (
        ApplicationBuilder()
        .token(bot_token)
        .concurrent_updates(True)
        .connection_pool_size(MAX_WORKERS * 2)
        .pool_timeout(180.0)
        .read_timeout(180.0)
        .write_timeout(180.0)
        .get_updates_read_timeout(180.0)
        .get_updates_write_timeout(180.0)
        .get_updates_pool_timeout(180.0)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("clean", clean))
    app.add_handler(CommandHandler("cards", cards))
    app.add_handler(CommandHandler("txt", txt))
    app.add_handler(CommandHandler("split", split))

    print("⚡ 𝗖𝗵𝘂𝘀𝗲𝗴𝗮?")
    
    app.run_polling(drop_pending_updates=True, allowed_updates=["message"])

if __name__ == "__main__":
    main()
