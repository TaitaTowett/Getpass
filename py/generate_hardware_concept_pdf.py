from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "hardware-design.pdf"
PAGE_W, PAGE_H = A4

NAVY = colors.HexColor("#14213d")
BLUE = colors.HexColor("#175cff")
BLUE_DARK = colors.HexColor("#123d91")
CYAN = colors.HexColor("#31c6f4")
MUTED = colors.HexColor("#62728b")
LINE = colors.HexColor("#dce5f2")
PALE = colors.HexColor("#f4f7fd")
WHITE = colors.white
GREEN = colors.HexColor("#18a76b")

BODY = ParagraphStyle(
    "Body",
    fontName="Helvetica",
    fontSize=8.5,
    leading=12,
    textColor=NAVY,
)
SMALL = ParagraphStyle(
    "Small",
    fontName="Helvetica",
    fontSize=7.4,
    leading=10,
    textColor=MUTED,
)
TABLE_TEXT = ParagraphStyle(
    "TableText",
    fontName="Helvetica",
    fontSize=7.3,
    leading=9.4,
    textColor=NAVY,
)
TABLE_BOLD = ParagraphStyle(
    "TableBold",
    parent=TABLE_TEXT,
    fontName="Helvetica-Bold",
)


def paragraph(
    pdf: canvas.Canvas,
    text: str,
    x: float,
    top: float,
    width: float,
    style: ParagraphStyle = BODY,
) -> float:
    item = Paragraph(text, style)
    _, height = item.wrap(width, PAGE_H)
    item.drawOn(pdf, x, top - height)
    return top - height


def header(pdf: canvas.Canvas, page: int, title: str, subtitle: str) -> float:
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(40, PAGE_H - 35, "GETPASS  /  READER HARDWARE CONCEPT")
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7.5)
    pdf.drawRightString(PAGE_W - 40, PAGE_H - 35, "R01  |  25 NOV 2026")
    pdf.setStrokeColor(LINE)
    pdf.line(40, PAGE_H - 45, PAGE_W - 40, PAGE_H - 45)
    pdf.setFillColor(NAVY)
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(40, PAGE_H - 78, title)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 8.5)
    pdf.drawString(40, PAGE_H - 94, subtitle)
    pdf.setStrokeColor(LINE)
    pdf.line(40, 35, PAGE_W - 40, 35)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7)
    pdf.drawString(40, 22, "CONCEPT ONLY  |  Verify hardware, SDK, dimensions and local requirements before procurement.")
    pdf.drawRightString(PAGE_W - 40, 22, f"{page} / 4")
    return PAGE_H - 116


def rounded_panel(
    pdf: canvas.Canvas,
    x: float,
    y: float,
    width: float,
    height: float,
    fill: colors.Color = WHITE,
    stroke: colors.Color = LINE,
) -> None:
    pdf.setFillColor(fill)
    pdf.setStrokeColor(stroke)
    pdf.roundRect(x, y, width, height, 12, stroke=1, fill=1)


def polygon(
    pdf: canvas.Canvas,
    points: list[tuple[float, float]],
    fill: colors.Color,
    stroke: colors.Color = BLUE_DARK,
) -> None:
    path = pdf.beginPath()
    path.moveTo(*points[0])
    for point in points[1:]:
        path.lineTo(*point)
    path.close()
    pdf.setFillColor(fill)
    pdf.setStrokeColor(stroke)
    pdf.setLineWidth(1.3)
    pdf.drawPath(path, stroke=1, fill=1)


def dimension(
    pdf: canvas.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    label: str,
    vertical: bool = False,
) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(BLUE)
    pdf.setLineWidth(0.8)
    pdf.line(x1, y1, x2, y2)
    if vertical:
        pdf.line(x1 - 4, y1, x1 + 4, y1)
        pdf.line(x2 - 4, y2, x2 + 4, y2)
        pdf.saveState()
        pdf.translate(x1 - 8, (y1 + y2) / 2)
        pdf.rotate(90)
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawCentredString(0, 0, label)
        pdf.restoreState()
    else:
        pdf.line(x1, y1 - 4, x1, y1 + 4)
        pdf.line(x2, y2 - 4, x2, y2 + 4)
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawCentredString((x1 + x2) / 2, y1 - 12, label)


def iso_scanner(pdf: canvas.Canvas, x: float, y: float) -> None:
    front_w, front_h, depth = 220, 145, 62
    front = [(x, y), (x + front_w, y), (x + front_w, y + front_h), (x, y + front_h)]
    top = [
        (x, y + front_h),
        (x + depth, y + front_h + 37),
        (x + front_w + depth, y + front_h + 37),
        (x + front_w, y + front_h),
    ]
    side = [
        (x + front_w, y),
        (x + front_w + depth, y + 37),
        (x + front_w + depth, y + front_h + 37),
        (x + front_w, y + front_h),
    ]
    polygon(pdf, top, colors.HexColor("#eaf1ff"))
    polygon(pdf, side, colors.HexColor("#194db8"))
    polygon(pdf, front, colors.HexColor("#dce8ff"))
    pdf.setFillColor(WHITE)
    pdf.setStrokeColor(colors.HexColor("#82a9ff"))
    pdf.roundRect(x + 33, y + front_h + 14, 150, 18, 5, stroke=1, fill=1)
    pdf.setFillColor(BLUE_DARK)
    pdf.roundRect(x + 97, y + front_h + 18, 24, 8, 3, stroke=0, fill=1)
    pdf.setFillColor(CYAN)
    pdf.circle(x + 109, y + front_h + 22, 2.5, stroke=0, fill=1)
    pdf.setFillColor(GREEN)
    pdf.circle(x + 17, y + 112, 3.2, stroke=0, fill=1)
    pdf.setFillColor(BLUE_DARK)
    pdf.setStrokeColor(colors.HexColor("#86adff"))
    pdf.roundRect(x + 158, y + 28, 42, 70, 9, stroke=1, fill=1)
    pdf.setStrokeColor(colors.HexColor("#c8e8ff"))
    pdf.setLineWidth(2)
    for offset in range(4):
        pdf.arc(
            x + 166 + offset * 4,
            y + 43 + offset * 2,
            x + 190 - offset * 4,
            y + 78 - offset * 2,
            20,
            145,
        )
    pdf.setStrokeColor(BLUE)
    pdf.setDash(4, 3)
    pdf.rect(x - 44, y + 4, 44, front_h - 8, stroke=1, fill=0)
    pdf.setDash()
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7)
    pdf.drawString(x - 42, y + front_h + 11, "FOLD-OUT SUPPORT")
    pdf.drawString(x + 25, y - 14, "FRONT: INTEGRATED FINGERPRINT SENSOR")
    pdf.drawString(x + 74, y + front_h + 47, "CAMERA + DIFFUSED LIGHT")


def draw_dimension_views(pdf: canvas.Canvas, top: float) -> None:
    panel_y = 456
    panel_h = top - panel_y
    panel_w = (PAGE_W - 100) / 3
    starts = [40, 50 + panel_w, 60 + 2 * panel_w]
    titles = ["TOP VIEW", "FRONT VIEW", "SIDE VIEW"]
    for x, title in zip(starts, titles):
        rounded_panel(pdf, x, panel_y, panel_w, panel_h)
        pdf.setFillColor(BLUE_DARK)
        pdf.setFont("Helvetica-Bold", 8)
        pdf.drawString(x + 12, top - 18, title)

    scale = 0.72
    body = 150 * scale

    x, y = starts[0], panel_y
    bx, by = x + 21, y + 67
    pdf.setStrokeColor(BLUE_DARK)
    pdf.setFillColor(colors.HexColor("#e8f0ff"))
    pdf.setDash(4, 3)
    pdf.rect(bx - 11, by, body + 22, body, stroke=1, fill=0)
    pdf.setDash()
    pdf.setFillColor(colors.HexColor("#dce8ff"))
    pdf.roundRect(bx, by, body, body, 7, stroke=1, fill=1)
    pdf.setFillColor(WHITE)
    pdf.roundRect(bx + 12, by + 23, body - 24, body - 42, 4, stroke=1, fill=1)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawCentredString(bx + body / 2, by + 5, "CARD / ID / PASSPORT")
    dimension(pdf, bx, by - 23, bx + body, by - 23, "150 mm")
    dimension(pdf, bx - 22, by, bx - 22, by + body, "150 mm", vertical=True)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawCentredString(x + panel_w / 2, panel_y + 19, "About 180 mm support width; 135 mm usable depth")

    x, y = starts[1], panel_y
    bx, by = x + 20, y + 67
    pdf.setFillColor(colors.HexColor("#dce8ff"))
    pdf.setStrokeColor(BLUE_DARK)
    pdf.roundRect(bx, by, body, body, 7, stroke=1, fill=1)
    pdf.setFillColor(BLUE_DARK)
    pdf.roundRect(bx + body - 45, by + 20, 33, 56, 6, stroke=0, fill=1)
    pdf.setFillColor(CYAN)
    pdf.circle(bx + 15, by + body - 16, 3, stroke=0, fill=1)
    dimension(pdf, bx, by - 23, bx + body, by - 23, "150 mm")
    dimension(pdf, bx - 19, by, bx - 19, by + body, "150 mm", vertical=True)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawString(bx + 2, by + 9, "FLUSH FINGER SENSOR")

    x, y = starts[2], panel_y
    bx, by = x + 22, y + 67
    pdf.setFillColor(colors.HexColor("#dce8ff"))
    pdf.setStrokeColor(BLUE_DARK)
    pdf.roundRect(bx, by, body, body, 7, stroke=1, fill=1)
    pdf.setFillColor(WHITE)
    pdf.setStrokeColor(BLUE)
    pdf.rect(bx + 22, by + body - 24, body - 44, 10, stroke=1, fill=1)
    pdf.setFillColor(BLUE_DARK)
    pdf.circle(bx + 66, by + body - 19, 3, stroke=0, fill=1)
    for vent in range(5):
        pdf.setStrokeColor(colors.HexColor("#6b91e5"))
        pdf.line(bx + 18 + vent * 9, by + 23, bx + 18 + vent * 9, by + 36)
    dimension(pdf, bx, by - 23, bx + body, by - 23, "150 mm")
    dimension(pdf, bx - 19, by, bx - 19, by + body, "150 mm", vertical=True)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawString(bx + 2, by + 9, "VENTED SIDE WALL")


def page_one(pdf: canvas.Canvas) -> None:
    top = header(
        pdf,
        1,
        "Two-station reader concept",
        "Compact document capture at entry; independent fingerprint verification at checkout.",
    )
    rounded_panel(pdf, 40, 382, PAGE_W - 80, 320, fill=PALE, stroke=LINE)
    iso_scanner(pdf, 145, 435)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(65, 658, "ENTRY UNIT")
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7)
    pdf.drawString(65, 644, "150 x 150 x 150 mm main enclosure")
    pdf.setStrokeColor(BLUE)
    pdf.line(125, 637, 185, 600)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(440, 552, "INTEGRATED")
    pdf.drawString(440, 540, "FINGERPRINT")
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7)
    pdf.drawString(440, 527, "reader sits on")
    pdf.drawString(440, 517, "front fascia")
    pdf.setStrokeColor(BLUE)
    pdf.line(438, 510, 405, 508)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(76, 459, "Passport support opens out")
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 7)
    pdf.drawString(76, 447, "Capture area about 180 x 135 mm in use")
    pdf.setStrokeColor(BLUE)
    pdf.line(151, 458, 127, 482)

    paragraph(
        pdf,
        "<b>Design intent.</b> Use a fixed-focus/auto-focus overhead document camera, diffuse illumination, a glare-controlled platen and a fold-out support. Place the fingerprint reader flush on the front slope for natural use at the gate.",
        44,
        359,
        PAGE_W - 88,
    )

    card_y, card_h = 110, 150
    half_w = (PAGE_W - 96) / 2
    rounded_panel(pdf, 40, card_y, half_w, card_h)
    rounded_panel(pdf, 56 + half_w, card_y, half_w, card_h)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(56, card_y + card_h - 23, "01  ENTRY DOCUMENT + FINGERPRINT")
    pdf.drawString(72 + half_w, card_y + card_h - 23, "02  CHECKOUT FINGERPRINT")
    paragraph(
        pdf,
        "First-time visitor: scan ID/passport fields, then locally enroll/match the fingerprint. Returning visitor: fingerprint lookup only. Device sends parsed fields and an opaque reader reference through the GETPASS bridge.",
        56,
        card_y + card_h - 39,
        half_w - 32,
        SMALL,
    )
    paragraph(
        pdf,
        "Separate desk USB reader verifies the active visitor locally. No ID scan is needed at exit. The bridge sends the match result and reference to GETPASS; the portal confirms the selected active visit.",
        72 + half_w,
        card_y + card_h - 39,
        half_w - 32,
        SMALL,
    )
    pdf.setFillColor(BLUE)
    pdf.setFont("Helvetica-Bold", 7.4)
    pdf.drawString(56, card_y + 20, "Prototype only; confirm SDK, OS and sensor fit before ordering.")
    pdf.drawString(72 + half_w, card_y + 20, "Use a separate device credential and USB port.")
    pdf.showPage()


def page_two(pdf: canvas.Canvas) -> None:
    top = header(
        pdf,
        2,
        "Dimensioned concept views",
        "Nominal outside envelope only. No manufacturing tolerances or tooling drawings are implied.",
    )
    draw_dimension_views(pdf, top)
    rounded_panel(pdf, 40, 266, PAGE_W - 80, 166)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(55, 413, "INTERNAL STACK / BUILD NOTES")
    notes = [
        ("A", "Camera board and lens mount in the upper lid; align optical axis over document centre."),
        ("B", "Diffuse LED bars on two sides; add matte baffles and test for laminate glare."),
        ("C", "Clear, replaceable platen; avoid permanent adhesive where cleaning is needed."),
        ("D", "Compute board, protected storage and USB hub below the platen; provide service access."),
        ("E", "Fingerprint reader mounted on the front face; keep vendor sensor opening unobstructed."),
    ]
    y = 392
    for key, text in notes:
        pdf.setFillColor(BLUE)
        pdf.circle(66, y + 2, 8, stroke=0, fill=1)
        pdf.setFillColor(WHITE)
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawCentredString(66, y, key)
        y = paragraph(pdf, text, 82, y + 7, PAGE_W - 160, SMALL) - 5

    rounded_panel(pdf, 40, 100, PAGE_W - 80, 142, fill=colors.HexColor("#f7f9fe"))
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(55, 222, "SEPARATE CHECKOUT READER")
    pdf.setFillColor(colors.HexColor("#eaf1ff"))
    pdf.setStrokeColor(BLUE_DARK)
    pdf.roundRect(67, 142, 126, 48, 12, stroke=1, fill=1)
    pdf.setFillColor(BLUE_DARK)
    pdf.roundRect(94, 151, 70, 34, 8, stroke=0, fill=1)
    pdf.setStrokeColor(colors.HexColor("#c8e8ff"))
    for offset in range(3):
        pdf.arc(110 + offset * 5, 159 + offset * 2, 149 - offset * 5, 177 - offset * 2, 20, 145)
    paragraph(
        pdf,
        "<b>Desk reader + cradle, not to scale.</b> The chosen USB fingerprint scanner is a vendor-supplied unit fitted into a simple anti-slip stand. Its body size and connector orientation vary by model; build the cradle after the exact part is selected.",
        218,
        199,
        PAGE_W - 275,
        BODY,
    )
    paragraph(
        pdf,
        "<b>Passport fit:</b> the shell is kept near 150 mm cubed; the support extends to about 180 mm width with roughly 135 mm usable capture depth. Confirm all passport pages and school-card formats with physical samples.",
        218,
        151,
        PAGE_W - 275,
        SMALL,
    )
    pdf.showPage()


def make_cost_table() -> Table:
    data = [
        [
            Paragraph("<b>Component</b>", TABLE_BOLD),
            Paragraph("<b>Qty</b>", TABLE_BOLD),
            Paragraph("<b>Unit price / assumption</b>", TABLE_BOLD),
            Paragraph("<b>Line budget</b>", TABLE_BOLD),
        ],
        [
            Paragraph("Pi 5 8GB board - prototype compute", TABLE_TEXT),
            "1",
            Paragraph("KES 19,500 listed", TABLE_TEXT),
            Paragraph("KES 19,500", TABLE_TEXT),
        ],
        [
            Paragraph("SecuGen Hamster Pro 20 - entry reader", TABLE_TEXT),
            "1",
            Paragraph("KES 16,704 listed", TABLE_TEXT),
            Paragraph("KES 16,704", TABLE_TEXT),
        ],
        [
            Paragraph("Autofocus document camera + mount", TABLE_TEXT),
            "1",
            Paragraph("KES 4,750-10,000 allowance", TABLE_TEXT),
            Paragraph("KES 4,750-10,000", TABLE_TEXT),
        ],
        [
            Paragraph("Diffuse LEDs, optical window, glass/platen, wiring", TABLE_TEXT),
            "1 set",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 2,000-5,000", TABLE_TEXT),
        ],
        [
            Paragraph("150 mm housing + fold-out support, prototype print", TABLE_TEXT),
            "1",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 4,000-10,000", TABLE_TEXT),
        ],
        [
            Paragraph("Power supply, cooling, storage and USB hub", TABLE_TEXT),
            "1 set",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 6,000-10,000", TABLE_TEXT),
        ],
        [
            Paragraph("<b>Entry unit subtotal</b>", TABLE_BOLD),
            "",
            "",
            Paragraph("<b>KES 52,954-71,204</b>", TABLE_BOLD),
        ],
        [
            Paragraph("SecuGen Hamster Pro 20 - checkout reader", TABLE_TEXT),
            "1",
            Paragraph("KES 16,704 listed", TABLE_TEXT),
            Paragraph("KES 16,704", TABLE_TEXT),
        ],
        [
            Paragraph("Checkout cradle / cable", TABLE_TEXT),
            "1",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 1,000-3,000", TABLE_TEXT),
        ],
        [
            Paragraph("LTE router / failover connection hardware", TABLE_TEXT),
            "1",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 4,000-10,000", TABLE_TEXT),
        ],
        [
            Paragraph("650VA UPS, 230V", TABLE_TEXT),
            "1",
            Paragraph("KES 9,500 listed", TABLE_TEXT),
            Paragraph("KES 9,500", TABLE_TEXT),
        ],
        [
            Paragraph("<b>Hardware total</b>", TABLE_BOLD),
            "",
            "",
            Paragraph("<b>KES 84,158-110,408</b>", TABLE_BOLD),
        ],
        [
            Paragraph("One-off SDK/bridge integration, case iteration and test", TABLE_TEXT),
            "1",
            Paragraph("Planning allowance", TABLE_TEXT),
            Paragraph("KES 25,000-70,000", TABLE_TEXT),
        ],
        [
            Paragraph("<b>Indicative first pilot</b>", TABLE_BOLD),
            "",
            Paragraph("<b>Hardware + one-time engineering</b>", TABLE_BOLD),
            Paragraph("<b>KES 109,158-180,408</b>", TABLE_BOLD),
        ],
    ]
    table = Table(data, colWidths=[205, 34, 128, 112], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf3ff")),
                ("TEXTCOLOR", (0, 0), (-1, 0), BLUE_DARK),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("BACKGROUND", (0, 7), (-1, 7), colors.HexColor("#f5f8ff")),
                ("BACKGROUND", (0, 12), (-1, 12), colors.HexColor("#f5f8ff")),
                ("BACKGROUND", (0, 14), (-1, 14), colors.HexColor("#e9f1ff")),
            ]
        )
    )
    return table


def page_three(pdf: canvas.Canvas) -> None:
    top = header(
        pdf,
        3,
        "Indicative budget in KES",
        "One entry station, one separate checkout sensor, shared network/power and a one-off integration allowance.",
    )
    table = make_cost_table()
    _, table_h = table.wrap(PAGE_W - 80, top)
    table.drawOn(pdf, 40, top - table_h - 8)
    note_top = top - table_h - 25
    paragraph(
        pdf,
        "<b>Not included:</b> taxes/import/delivery, gate monitor or PC, monthly SIM/data, cloud hosting, production tooling, warranty/spares, or commercial OCR/SDK licence fees. If the fingerprint vendor does not support Raspberry Pi/Linux, replace it with a supported compact x86 host and re-quote; allow roughly KES 10,500-35,500 extra versus the listed Pi board.",
        42,
        note_top,
        PAGE_W - 84,
        SMALL,
    )
    paragraph(
        pdf,
        "<b>Estimate method.</b> Retailer listings are point-in-time references; remaining amounts are planning allowances rather than supplier quotes. A first prototype may cost more after sensor brackets, cable routing, OCR tuning, repeatability tests and enclosure revisions.",
        42,
        note_top - 56,
        PAGE_W - 84,
        SMALL,
    )
    pdf.showPage()


def flow_box(
    pdf: canvas.Canvas,
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    body: str,
) -> None:
    rounded_panel(pdf, x, y, width, height, fill=WHITE)
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(x + 9, y + height - 17, title)
    paragraph(pdf, body, x + 9, y + height - 26, width - 18, SMALL)


def page_four(pdf: canvas.Canvas) -> None:
    top = header(
        pdf,
        4,
        "Integration, uptime and privacy",
        "API-compatible concept; individual scanner drivers, OCR and offline replay still require engineering.",
    )
    gap = 9
    box_w = (PAGE_W - 80 - gap * 4) / 5
    titles = [
        ("1  CAPTURE", "Camera reads document locally; parse fields and discard temporary image."),
        ("2  MATCH", "Fingerprint match on reader side; retain only protected local templates."),
        ("3  BRIDGE", "HTTPS POST /api/reader/verifications with a per-device token."),
        ("4  API + DB", "GETPASS validates and persists encrypted visitor fields and event time."),
        ("5  CONFIRM", "Gate UI confirms only after the central API response is received."),
    ]
    x = 40
    for index, (title, body) in enumerate(titles):
        flow_box(pdf, x, top - 103, box_w, 91, title, body)
        if index < len(titles) - 1:
            pdf.setFillColor(BLUE)
            pdf.setFont("Helvetica-Bold", 15)
            pdf.drawCentredString(x + box_w + gap / 2, top - 60, ">")
        x += box_w + gap

    row_y = top - 132
    column_gap = 12
    column_w = (PAGE_W - 80 - column_gap) / 2
    rounded_panel(pdf, 40, row_y - 125, column_w, 118, fill=colors.HexColor("#f8faff"))
    rounded_panel(pdf, 52 + column_w, row_y - 125, column_w, 118, fill=colors.HexColor("#f8faff"))
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(54, row_y - 25, "REALTIME WITH HONEST OFFLINE HANDLING")
    paragraph(
        pdf,
        "Use wired Ethernet with 4G failover, UPS, health checks and a durable encrypted edge outbox. GETPASS needs idempotent event replay before offline events can be safely synchronized. During an outage, show “pending sync”; do not report the event as centrally recorded until acknowledged. Zero downtime or zero latency cannot be guaranteed.",
        54,
        row_y - 38,
        column_w - 28,
        SMALL,
    )
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(66 + column_w, row_y - 25, "PRIVACY + DEVICE SECURITY")
    paragraph(
        pdf,
        "No fingerprint image/template is accepted by the current API. Keep biometric templates on the reader-side system; encrypt local storage; use unique, revocable reader tokens and TLS; delete temporary document images. Before a live school deployment, review lawful basis, retention, access controls, breach process and DPIA/ODPC obligations.",
        66 + column_w,
        row_y - 38,
        column_w - 28,
        SMALL,
    )

    test_top = row_y - 147
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(42, test_top, "PROTOTYPE ACCEPTANCE CHECKS")
    checks = [
        "1. Test real Kenyan ID, school ID and passport samples; measure OCR correction rate and false reads.",
        "2. Verify supported camera/fingerprint drivers, local matching, liveness features and SDK licence on chosen OS.",
        "3. Exercise first-time and repeat check-in, checkout-to-active-visit matching, reader revocation and retries.",
        "4. Disconnect power/network; ensure pending events survive restart and replay once after idempotency is implemented.",
    ]
    y = test_top - 14
    for item in checks:
        y = paragraph(pdf, item, 48, y, PAGE_W - 96, SMALL) - 3

    source_top = y - 9
    pdf.setFillColor(BLUE_DARK)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(42, source_top, "PRICE REFERENCES CHECKED 25 NOV 2026")
    source_text = (
        '<link href="https://nebulahub.co.ke/product/secugen-hamster-pro-20/">SecuGen Hamster Pro 20: KES 16,704</link>  |  '
        '<link href="https://store.nerokas.co.ke/SKU-3877">Nerokas Pi 5 8GB: KES 19,500 shown in listing</link><br/>'
        '<link href="https://www.jumia.co.ke/slp/raspberry-pi-camera-module">Jumia camera listing: KES 4,750; confirm autofocus model</link>  |  '
        '<link href="https://smartbuy.co.ke/product/apc-650va/">SmartBuy APC 650VA, 230V: KES 9,500</link><br/>'
        '<link href="https://www.satoprints.co.ke/guides/how-much-does-3d-printing-cost-in-kenya">SatoPrints: typical catalogue print range KES 200-5,800; custom parts vary</link>  |  '
        '<link href="https://www.jumia.co.ke/catalog/?q=4g+lte+router">Jumia 4G router search: generic hotspot listings from about KES 2,265</link>'
    )
    paragraph(pdf, source_text, 42, source_top - 7, PAGE_W - 84, SMALL)
    pdf.showPage()


def main() -> None:
    pdf = canvas.Canvas(str(OUTPUT), pagesize=A4, pageCompression=1)
    pdf.setTitle("GETPASS Reader Hardware Concept")
    pdf.setAuthor("GETPASS")
    pdf.setSubject("Concept design, integration notes and indicative Kenya-shilling budget")
    page_one(pdf)
    page_two(pdf)
    page_three(pdf)
    page_four(pdf)
    pdf.save()
    print(f"Generated {OUTPUT}")


if __name__ == "__main__":
    main()
