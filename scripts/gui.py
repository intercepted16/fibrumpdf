#!/usr/bin/env python3
"""AI generated script, just for me to quickly visualise the output in Markdown. Not safe for real usage."""

import sys
import streamlit as st
from time import perf_counter
from fibrum_pdf import to_json


def main(input_pdf: str, output_file: str):
    st.set_page_config(
        page_title="PDF Viewer", layout="wide", initial_sidebar_state="expanded"
    )

    # Extract PDF
    if "extraction_done" not in st.session_state:
        with st.spinner("🔄 Extracting PDF..."):
            start = perf_counter()
            result = to_json(input_pdf, output=output_file)
            end = perf_counter()

        st.session_state.extraction_done = True
        st.session_state.result = result
        st.session_state.pages = []
        st.session_state.iterator = iter(result)
        st.session_state.loading = True
        st.session_state.current_idx = 0

        st.success(f"✓ Extracted in {end - start:.2f}s")

    # Load pages on demand
    def load_page(idx: int):
        while len(st.session_state.pages) <= idx and st.session_state.loading:
            try:
                page = next(st.session_state.iterator)
                st.session_state.pages.append(page.markdown)
            except StopIteration:
                st.session_state.loading = False

        return (
            st.session_state.pages[idx] if idx < len(st.session_state.pages) else None
        )

    # Sidebar controls
    st.sidebar.markdown("## Navigation")
    total = (
        len(st.session_state.pages)
        if not st.session_state.loading
        else f"{len(st.session_state.pages)}+"
    )
    st.sidebar.markdown(f"**Page {st.session_state.current_idx + 1} / {total}**")

    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("← Previous", disabled=st.session_state.current_idx == 0):
            st.session_state.current_idx -= 1
            st.rerun()

    with col2:
        next_available = load_page(st.session_state.current_idx + 1) is not None
        if st.button("Next →", disabled=not next_available):
            st.session_state.current_idx += 1
            st.rerun()

    st.sidebar.markdown(
        f"**Status:** {'🔄 Loading...' if st.session_state.loading else '✓ Done'}"
    )

    # Display current page
    content = load_page(st.session_state.current_idx)

    if content:
        st.markdown(
            content, unsafe_allow_html=True
        )  # this is a one-off script, allow it.
    else:
        st.info("No pages available yet")


if __name__ == "__main__":
    argv = sys.argv.copy()
    argv.pop(0)

    if len(argv) < 2:
        print(f"Usage: `streamlit run {sys.argv[0]} -- <input_pdf> <output_file>`")
        sys.exit(1)

    _in = argv[0]
    _out = argv[1]

    main(_in, _out)
