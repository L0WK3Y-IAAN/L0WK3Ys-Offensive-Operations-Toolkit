#!/usr/bin/env python3
# MRET: no_args
"""
Multithreaded Frida Script Downloader from codeshare.frida.re, with:
  - Selenium fallback for dynamic Ace Editor code
  - Auto-completion for the search query via prompt_toolkit

Removes the debug HTML saving logic, since Selenium covers dynamic code.

1. Detects max pages by parsing the first page's pagination links.
2. Spawns threads to fetch each page concurrently.
3. Collects all script entries from <article> blocks.
4. Displays them in a table, allows interactive search (with auto-completion),
   and downloads script code (via static parse or Selenium fallback).
"""

import os
import re
import sys
import time
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from concurrent.futures import ThreadPoolExecutor, as_completed

# prompt_toolkit for auto-completion
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

# Selenium for dynamic code fallback
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

console = Console()

BASE_URL = "https://codeshare.frida.re"
BROWSE_BASE = f"{BASE_URL}/browse?page="

# -----------------------------------------------------------------------------
# Page fetching
# -----------------------------------------------------------------------------

def fetch_page(url):
    """Fetch HTML from a URL, returning the text or None on failure."""
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        console.print(f"[red]Error fetching page {url}: {e}[/]")
        return None

def parse_articles(html):
    """Parse <article> blocks from the raw HTML. Returns a list of dicts."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    articles = soup.find_all("article")
    entries = []

    for art in articles:
        h2 = art.find("h2")
        if not h2:
            continue
        link_tag = h2.find("a")
        if not link_tag:
            continue

        title = link_tag.get_text(strip=True)
        page_url = link_tag["href"]
        if not page_url.startswith("http"):
            page_url = BASE_URL + page_url

        author_tag = art.find("h4")
        author = author_tag.get_text(strip=True) if author_tag else "Unknown"

        desc_tag = art.find("p")
        description = desc_tag.get_text(strip=True) if desc_tag else ""

        entries.append({
            "title": title,
            "author": author,
            "description": description,
            "page_url": page_url
        })
    return entries

def get_max_page(first_page_html):
    """Determines the maximum page number from pagination links."""
    soup = BeautifulSoup(first_page_html, "html.parser")
    page_links = soup.select('li a[href^="?page="]')
    max_page = 1
    for link in page_links:
        text = link.get_text(strip=True)
        if text.isdigit():
            p = int(text)
            if p > max_page:
                max_page = p
    return max_page

def fetch_and_parse_page(page_num):
    """Fetches a single page and returns parsed articles."""
    url = f"{BROWSE_BASE}{page_num}"
    html = fetch_page(url)
    entries = parse_articles(html)
    return entries

def crawl_all_pages():
    """Fetch all pages from codeshare.frida.re/browse, multi-threaded."""
    console.print("[cyan]Fetching page 1 to detect pagination...[/]")
    first_page_html = fetch_page(BROWSE_BASE + "1")
    if not first_page_html:
        return []

    max_page = get_max_page(first_page_html)
    console.print(f"[yellow]Detected up to page {max_page}[/]")

    all_entries = parse_articles(first_page_html)
    if max_page == 1:
        return all_entries

    console.print(f"[cyan]Spawning threads to fetch pages 2..{max_page}[/]")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for page in range(2, max_page + 1):
            futures.append(executor.submit(fetch_and_parse_page, page))

        for fut in as_completed(futures):
            data = fut.result()
            all_entries.extend(data)

    return all_entries

# -----------------------------------------------------------------------------
# Table & Auto-Complete Search
# -----------------------------------------------------------------------------

def build_autocompleter(entries):
    """Gather unique words from title, author, description for auto-completion."""
    words = set()
    for e in entries:
        text = f"{e['title']} {e['author']} {e['description']}"
        for w in text.lower().split():
            w = re.sub(r"[^\w]+", "", w)
            if w:
                words.add(w)
    return WordCompleter(sorted(words), ignore_case=True)

def interactive_search(entries):
    """Prompt user for a search query with auto-completion from prompt_toolkit."""
    search_completer = build_autocompleter(entries)
    session = PromptSession()

    console.print("[bold cyan]Type your search (press Enter to skip). Auto-completion enabled![/]")
    query = session.prompt("Search Query: ", completer=search_completer).strip().lower()
    if not query:
        return entries

    filtered = []
    for e in entries:
        text = f"{e['title']} {e['author']} {e['description']}".lower()
        if query in text:
            filtered.append(e)
    return filtered

def display_table(entries):
    table = Table(title="Frida Scripts on codeshare.frida.re", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Title", style="green")
    table.add_column("Author", style="yellow")
    table.add_column("Description", style="white")

    for i, e in enumerate(entries, 1):
        desc = e["description"][:60] + ("..." if len(e["description"]) > 60 else "")
        table.add_row(str(i), e["title"], e["author"], desc)

    console.print(table)

# -----------------------------------------------------------------------------
# Selenium-based fallback
# -----------------------------------------------------------------------------

def fetch_ace_code_selenium(url):
    """
    Launch Selenium headless, load the page, wait ~5s,
    then scrape .ace_line elements from the final DOM.
    """
    console.print("[cyan]Using fallback to load dynamic editor code...[/]")

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")

    driver = webdriver.Chrome(options=chrome_options)
    try:
        driver.get(url)
        time.sleep(5)  # Let the page scripts run

        rendered_html = driver.page_source
        soup = BeautifulSoup(rendered_html, "html.parser")

        code_lines = []

        # 1) <div id="editor"> with .ace_line
        editor_div = soup.find("div", id="editor")
        if editor_div:
            line_tags = editor_div.find_all(lambda tag:
                tag.name == "div" and tag.get("class") and "ace_line" in tag["class"]
            )
            if line_tags:
                code_lines = [t.get_text() for t in line_tags]
            else:
                # fallback .ace_layer.ace_text-layer
                text_layer = editor_div.select_one("div.ace_layer.ace_text-layer")
                if text_layer:
                    line_divs = text_layer.select("div.ace_line")
                    code_lines = [ld.get_text() for ld in line_divs]
        else:
            # 2) final fallback: any .ace_layer.ace_text-layer
            text_layer = soup.select_one("div.ace_layer.ace_text-layer")
            if text_layer:
                line_divs = text_layer.select("div.ace_line")
                code_lines = [ld.get_text() for ld in line_divs]

        if code_lines:
            return "\n".join(code_lines)
        else:
            console.print("[red]Selenium: No .ace_line elements found after rendering.[/]")
            return None

    finally:
        driver.quit()

# -----------------------------------------------------------------------------
# Download script code
# -----------------------------------------------------------------------------

def download_script_code(page_url):
    """
    1) Attempt to parse static HTML.
    2) If not found, fallback to Selenium.
    """
    html = fetch_page(page_url)
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    code = None

    console.print("[cyan]Attempting to parse code...[/]")
    editor_div = soup.find("div", id="editor")
    if editor_div:
        line_tags = editor_div.find_all(lambda tag:
            tag.name == "div" and tag.get("class") and "ace_line" in tag["class"]
        )
        if line_tags:
            code = "\n".join([tag.get_text() for tag in line_tags])
        else:
            text_layer = editor_div.select_one("div.ace_layer.ace_text-layer")
            if text_layer:
                line_divs = text_layer.select("div.ace_line")
                if line_divs:
                    code = "\n".join([div.get_text() for div in line_divs])

    # If no code found, fallback to Selenium
    if not code:
        console.print("[yellow]No editor code in static HTML. Attempting fallback...[/]")
        code = fetch_ace_code_selenium(page_url)

    if not code:
        console.print("[red]Could not retrieve Ace Editor code even with Selenium. Aborting.[/]")
        return

    # Construct a safe filename
    filename = page_url.rstrip("/").split("/")[-1] + ".js"
    filename = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)

    scripts_folder = os.path.join(os.path.dirname(__file__), "scripts")
    if not os.path.exists(scripts_folder):
        os.makedirs(scripts_folder)

    file_path = os.path.join(scripts_folder, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(code)

    console.print(f"[green]Script saved to: {file_path}[/]")

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    console.print("\n[bold magenta]Multithreaded Frida Script Downloader (Selenium + Autocomplete)[/]\n")

    all_entries = crawl_all_pages()
    if not all_entries:
        console.print("[red]No script entries found![/]")
        return

    filtered = interactive_search(all_entries)
    if not filtered:
        console.print("[red]No results match your query.[/]")
        return

    display_table(filtered)

    while True:
        choice = Prompt.ask("[bold cyan]Enter the number of the script to download (or 'q' to quit)[/]").strip()
        if choice.lower() == 'q':
            console.print("[yellow]Exiting...[/]")
            break

        if not choice.isdigit():
            console.print("[red]Invalid selection. Try again.[/]")
            continue

        idx = int(choice)
        if 1 <= idx <= len(filtered):
            selected = filtered[idx - 1]
            console.print(f"[cyan]Downloading script: {selected['title']}[/]")
            download_script_code(selected["page_url"])
            break
        else:
            console.print("[red]Invalid selection. Try again.[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)
