/**
 * High-Value Products Database ($10,000+ items)
 * Curated list of famous art, collectible watches, rare sneakers, trading cards, etc.
 * Used for product model autocomplete after brand selection
 */

export interface ProductModel {
  name: string;
  brand: string;
  category: string;
  estimatedValue?: string;  // e.g., "$15,000-$50,000"
  year?: number;
  aliases?: string[];
}

// ==================== ROLEX WATCHES ($10k+) ====================
const ROLEX: ProductModel[] = [
  { name: 'Submariner', brand: 'Rolex', category: 'watches', estimatedValue: '$10,000-$15,000', aliases: ['Sub'] },
  { name: 'Submariner Date', brand: 'Rolex', category: 'watches', estimatedValue: '$12,000-$18,000' },
  { name: 'Submariner No Date', brand: 'Rolex', category: 'watches', estimatedValue: '$10,000-$14,000' },
  { name: 'Daytona', brand: 'Rolex', category: 'watches', estimatedValue: '$30,000-$50,000' },
  { name: 'Daytona Cosmograph', brand: 'Rolex', category: 'watches', estimatedValue: '$35,000-$100,000+' },
  { name: 'GMT-Master II', brand: 'Rolex', category: 'watches', estimatedValue: '$15,000-$25,000', aliases: ['GMT', 'Pepsi', 'Batman', 'Sprite'] },
  { name: 'GMT-Master II Pepsi', brand: 'Rolex', category: 'watches', estimatedValue: '$20,000-$30,000' },
  { name: 'GMT-Master II Batman', brand: 'Rolex', category: 'watches', estimatedValue: '$18,000-$25,000' },
  { name: 'Datejust 41', brand: 'Rolex', category: 'watches', estimatedValue: '$10,000-$15,000' },
  { name: 'Datejust 36', brand: 'Rolex', category: 'watches', estimatedValue: '$8,000-$12,000' },
  { name: 'Day-Date', brand: 'Rolex', category: 'watches', estimatedValue: '$25,000-$50,000', aliases: ['President'] },
  { name: 'Day-Date 40', brand: 'Rolex', category: 'watches', estimatedValue: '$35,000-$60,000' },
  { name: 'Explorer', brand: 'Rolex', category: 'watches', estimatedValue: '$10,000-$15,000' },
  { name: 'Explorer II', brand: 'Rolex', category: 'watches', estimatedValue: '$12,000-$18,000' },
  { name: 'Sea-Dweller', brand: 'Rolex', category: 'watches', estimatedValue: '$15,000-$20,000' },
  { name: 'Deepsea', brand: 'Rolex', category: 'watches', estimatedValue: '$15,000-$20,000' },
  { name: 'Yacht-Master', brand: 'Rolex', category: 'watches', estimatedValue: '$15,000-$25,000' },
  { name: 'Yacht-Master II', brand: 'Rolex', category: 'watches', estimatedValue: '$20,000-$30,000' },
  { name: 'Sky-Dweller', brand: 'Rolex', category: 'watches', estimatedValue: '$20,000-$50,000' },
  { name: 'Milgauss', brand: 'Rolex', category: 'watches', estimatedValue: '$12,000-$18,000' },
  { name: 'Air-King', brand: 'Rolex', category: 'watches', estimatedValue: '$8,000-$12,000' },
  { name: 'Oyster Perpetual', brand: 'Rolex', category: 'watches', estimatedValue: '$6,000-$10,000' },
  // Vintage
  { name: 'Paul Newman Daytona', brand: 'Rolex', category: 'watches', estimatedValue: '$200,000-$5,000,000+' },
  { name: 'Vintage Submariner 5513', brand: 'Rolex', category: 'watches', estimatedValue: '$15,000-$30,000' },
  { name: 'Vintage GMT-Master 1675', brand: 'Rolex', category: 'watches', estimatedValue: '$20,000-$50,000' },
];

// ==================== PATEK PHILIPPE ($10k+) ====================
const PATEK: ProductModel[] = [
  { name: 'Nautilus 5711', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$100,000-$200,000' },
  { name: 'Nautilus 5712', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$80,000-$150,000' },
  { name: 'Nautilus Chronograph 5980', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$100,000-$180,000' },
  { name: 'Aquanaut 5167', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$40,000-$80,000' },
  { name: 'Aquanaut 5168', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$50,000-$100,000' },
  { name: 'Calatrava', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$20,000-$50,000' },
  { name: 'Calatrava 5196', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$25,000-$40,000' },
  { name: 'Annual Calendar 5396', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$40,000-$60,000' },
  { name: 'Perpetual Calendar 5320', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$80,000-$120,000' },
  { name: 'World Time 5230', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$50,000-$80,000' },
  { name: 'Grand Complications', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$100,000-$1,000,000+' },
  { name: 'Chronograph 5170', brand: 'Patek Philippe', category: 'watches', estimatedValue: '$60,000-$100,000' },
];

// ==================== AUDEMARS PIGUET ($10k+) ====================
const AP: ProductModel[] = [
  { name: 'Royal Oak 15500', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$30,000-$50,000' },
  { name: 'Royal Oak 15202', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$80,000-$150,000', aliases: ['Jumbo'] },
  { name: 'Royal Oak Chronograph', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$40,000-$80,000' },
  { name: 'Royal Oak Offshore', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$25,000-$60,000' },
  { name: 'Royal Oak Offshore Diver', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$25,000-$40,000' },
  { name: 'Royal Oak Perpetual Calendar', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$100,000-$200,000' },
  { name: 'Royal Oak Tourbillon', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$150,000-$500,000+' },
  { name: 'Code 11.59', brand: 'Audemars Piguet', category: 'watches', estimatedValue: '$25,000-$80,000' },
];

// ==================== OTHER LUXURY WATCHES ($10k+) ====================
const OTHER_WATCHES: ProductModel[] = [
  // Richard Mille
  { name: 'RM 011', brand: 'Richard Mille', category: 'watches', estimatedValue: '$150,000-$300,000' },
  { name: 'RM 035', brand: 'Richard Mille', category: 'watches', estimatedValue: '$100,000-$200,000' },
  { name: 'RM 055', brand: 'Richard Mille', category: 'watches', estimatedValue: '$150,000-$250,000' },
  { name: 'RM 027', brand: 'Richard Mille', category: 'watches', estimatedValue: '$500,000-$1,000,000+' },
  // Omega
  { name: 'Speedmaster Moonwatch', brand: 'Omega', category: 'watches', estimatedValue: '$6,000-$15,000' },
  { name: 'Speedmaster Professional', brand: 'Omega', category: 'watches', estimatedValue: '$6,000-$12,000' },
  { name: 'Seamaster 300M', brand: 'Omega', category: 'watches', estimatedValue: '$5,000-$8,000' },
  { name: 'Seamaster Planet Ocean', brand: 'Omega', category: 'watches', estimatedValue: '$6,000-$12,000' },
  // Cartier
  { name: 'Santos', brand: 'Cartier', category: 'watches', estimatedValue: '$8,000-$20,000' },
  { name: 'Tank', brand: 'Cartier', category: 'watches', estimatedValue: '$5,000-$30,000' },
  { name: 'Ballon Bleu', brand: 'Cartier', category: 'watches', estimatedValue: '$6,000-$15,000' },
  // Vacheron Constantin
  { name: 'Overseas', brand: 'Vacheron Constantin', category: 'watches', estimatedValue: '$20,000-$50,000' },
  { name: 'Patrimony', brand: 'Vacheron Constantin', category: 'watches', estimatedValue: '$20,000-$40,000' },
  { name: 'Traditionnelle', brand: 'Vacheron Constantin', category: 'watches', estimatedValue: '$25,000-$100,000' },
  // A. Lange & Söhne
  { name: 'Lange 1', brand: 'A. Lange & Söhne', category: 'watches', estimatedValue: '$30,000-$60,000' },
  { name: 'Saxonia', brand: 'A. Lange & Söhne', category: 'watches', estimatedValue: '$15,000-$40,000' },
  { name: 'Zeitwerk', brand: 'A. Lange & Söhne', category: 'watches', estimatedValue: '$80,000-$150,000' },
  // F.P. Journe
  { name: 'Chronomètre Bleu', brand: 'F.P. Journe', category: 'watches', estimatedValue: '$30,000-$60,000' },
  { name: 'Chronomètre Souverain', brand: 'F.P. Journe', category: 'watches', estimatedValue: '$40,000-$80,000' },
];

// ==================== AIR JORDAN SNEAKERS ($10k+) ====================
const JORDAN: ProductModel[] = [
  // Air Jordan 1
  { name: 'Air Jordan 1 Chicago (1985)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$50,000+', year: 1985 },
  { name: 'Air Jordan 1 Bred (1985)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$30,000', year: 1985 },
  { name: 'Air Jordan 1 Royal (1985)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$25,000', year: 1985 },
  { name: 'Air Jordan 1 Dior', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$20,000', year: 2020 },
  { name: 'Air Jordan 1 Travis Scott', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$1,500-$3,000', aliases: ['Cactus Jack'] },
  { name: 'Air Jordan 1 Fragment x Travis Scott', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$2,000-$4,000' },
  // Air Jordan 3
  { name: 'Air Jordan 3 Black Cement (1988)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$30,000', year: 1988 },
  { name: 'Air Jordan 3 White Cement (1988)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$25,000', year: 1988 },
  // Air Jordan 4
  { name: 'Air Jordan 4 Bred (1989)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$25,000', year: 1989 },
  { name: 'Air Jordan 4 Eminem Encore', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$20,000-$50,000' },
  { name: 'Air Jordan 4 Undefeated', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$15,000-$30,000' },
  // Air Jordan 5
  { name: 'Air Jordan 5 Grape (1990)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$20,000', year: 1990 },
  // Air Jordan 11
  { name: 'Air Jordan 11 Concord (1995)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$25,000', year: 1995 },
  { name: 'Air Jordan 11 Bred (1995)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$20,000', year: 1995 },
  { name: 'Air Jordan 11 Space Jam (1995)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$10,000-$20,000', year: 1995 },
  // Game-Worn
  { name: 'Game-Worn Air Jordan (Any)', brand: 'Air Jordan', category: 'sneakers', estimatedValue: '$50,000-$500,000+' },
];

// ==================== NIKE/OTHER SNEAKERS ($10k+) ====================
const NIKE_SNEAKERS: ProductModel[] = [
  { name: 'Nike MAG Back to the Future', brand: 'Nike', category: 'sneakers', estimatedValue: '$30,000-$100,000+', year: 2011 },
  { name: 'Nike MAG Self-Lacing', brand: 'Nike', category: 'sneakers', estimatedValue: '$50,000-$150,000', year: 2016 },
  { name: 'Nike Dunk SB Paris', brand: 'Nike', category: 'sneakers', estimatedValue: '$20,000-$50,000' },
  { name: 'Nike Dunk SB Pigeon', brand: 'Nike', category: 'sneakers', estimatedValue: '$15,000-$30,000' },
  { name: 'Nike Dunk SB Freddy Krueger', brand: 'Nike', category: 'sneakers', estimatedValue: '$10,000-$25,000' },
  { name: 'Nike Air Yeezy 2 Red October', brand: 'Nike', category: 'sneakers', estimatedValue: '$10,000-$20,000' },
  { name: 'Nike Moon Shoe', brand: 'Nike', category: 'sneakers', estimatedValue: '$400,000+', year: 1972 },
];

// ==================== POKEMON CARDS ($10k+) ====================
const POKEMON: ProductModel[] = [
  // Base Set
  { name: 'Charizard 1st Edition Base Set', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$50,000-$500,000+', year: 1999 },
  { name: 'Charizard Shadowless Base Set', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$10,000-$50,000', year: 1999 },
  { name: 'Blastoise 1st Edition Base Set', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$10,000-$50,000', year: 1999 },
  { name: 'Venusaur 1st Edition Base Set', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$10,000-$40,000', year: 1999 },
  { name: 'Base Set 1st Edition Booster Box', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$300,000-$500,000+' },
  // Promos
  { name: 'Pikachu Illustrator', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$1,000,000-$6,000,000+', year: 1998 },
  { name: 'Trophy Pikachu Gold', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$100,000-$300,000' },
  { name: 'Pre-Release Raichu', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$10,000-$50,000' },
  { name: 'No. 1 Trainer', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$50,000-$150,000' },
  // Japanese
  { name: 'Tamamushi University Magikarp', brand: 'Pokemon', category: 'trading_cards', estimatedValue: '$50,000-$100,000' },
];

// ==================== MAGIC: THE GATHERING ($10k+) ====================
const MTG: ProductModel[] = [
  { name: 'Black Lotus Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$100,000-$500,000+', year: 1993 },
  { name: 'Black Lotus Beta', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$50,000-$200,000', year: 1993 },
  { name: 'Ancestral Recall Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$20,000-$100,000', year: 1993 },
  { name: 'Time Walk Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$80,000', year: 1993 },
  { name: 'Mox Sapphire Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$60,000', year: 1993 },
  { name: 'Mox Ruby Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$50,000', year: 1993 },
  { name: 'Mox Pearl Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$50,000', year: 1993 },
  { name: 'Mox Jet Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$50,000', year: 1993 },
  { name: 'Mox Emerald Alpha', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$15,000-$50,000', year: 1993 },
  { name: 'Alpha Booster Box', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$500,000+', year: 1993 },
  { name: 'Beta Booster Box', brand: 'Magic: The Gathering', category: 'trading_cards', estimatedValue: '$200,000+', year: 1993 },
];

// ==================== SPORTS CARDS ($10k+) ====================
const SPORTS_CARDS: ProductModel[] = [
  // Baseball
  { name: 'T206 Honus Wagner', brand: 'Topps', category: 'trading_cards', estimatedValue: '$1,000,000-$7,000,000+', year: 1909 },
  { name: '1952 Topps Mickey Mantle #311', brand: 'Topps', category: 'trading_cards', estimatedValue: '$100,000-$12,000,000+', year: 1952 },
  { name: '1951 Bowman Mickey Mantle RC', brand: 'Bowman', category: 'trading_cards', estimatedValue: '$50,000-$500,000', year: 1951 },
  { name: '1914 Babe Ruth Baltimore News', brand: 'Baltimore News', category: 'trading_cards', estimatedValue: '$500,000+', year: 1914 },
  // Basketball
  { name: '1986 Fleer Michael Jordan RC #57', brand: 'Fleer', category: 'trading_cards', estimatedValue: '$50,000-$1,000,000+', year: 1986 },
  { name: '2003 Upper Deck Exquisite LeBron James RC', brand: 'Upper Deck', category: 'trading_cards', estimatedValue: '$100,000-$5,000,000+', year: 2003 },
  { name: '2018 Panini National Treasures Luka Doncic RC', brand: 'Panini', category: 'trading_cards', estimatedValue: '$50,000-$500,000', year: 2018 },
  // Football
  { name: '2000 Playoff Contenders Tom Brady RC Auto', brand: 'Playoff', category: 'trading_cards', estimatedValue: '$100,000-$3,000,000+', year: 2000 },
  { name: '2017 Panini National Treasures Patrick Mahomes RC', brand: 'Panini', category: 'trading_cards', estimatedValue: '$50,000-$500,000', year: 2017 },
];

// ==================== FAMOUS ARTWORKS ($10k+) ====================
const ARTWORKS: ProductModel[] = [
  // Leonardo da Vinci
  { name: 'Mona Lisa', brand: 'Leonardo da Vinci', category: 'art', estimatedValue: 'Priceless ($800M+)' },
  { name: 'The Last Supper', brand: 'Leonardo da Vinci', category: 'art', estimatedValue: 'Priceless' },
  { name: 'Salvator Mundi', brand: 'Leonardo da Vinci', category: 'art', estimatedValue: '$450,000,000' },
  { name: 'Vitruvian Man', brand: 'Leonardo da Vinci', category: 'art', estimatedValue: 'Priceless' },
  // Vincent van Gogh
  { name: 'Starry Night', brand: 'Vincent van Gogh', category: 'art', estimatedValue: 'Priceless ($100M+)' },
  { name: 'Sunflowers', brand: 'Vincent van Gogh', category: 'art', estimatedValue: '$40,000,000-$100,000,000' },
  { name: 'Irises', brand: 'Vincent van Gogh', category: 'art', estimatedValue: '$54,000,000+' },
  { name: 'Portrait of Dr. Gachet', brand: 'Vincent van Gogh', category: 'art', estimatedValue: '$82,500,000' },
  { name: 'Self-Portrait', brand: 'Vincent van Gogh', category: 'art', estimatedValue: '$50,000,000+' },
  // Pablo Picasso
  { name: 'Les Demoiselles d\'Avignon', brand: 'Pablo Picasso', category: 'art', estimatedValue: 'Priceless' },
  { name: 'Guernica', brand: 'Pablo Picasso', category: 'art', estimatedValue: 'Priceless ($200M+)' },
  { name: 'Les Femmes d\'Alger', brand: 'Pablo Picasso', category: 'art', estimatedValue: '$179,000,000' },
  { name: 'The Old Guitarist', brand: 'Pablo Picasso', category: 'art', estimatedValue: '$100,000,000+' },
  { name: 'Boy with a Pipe', brand: 'Pablo Picasso', category: 'art', estimatedValue: '$104,000,000' },
  // Claude Monet
  { name: 'Water Lilies', brand: 'Claude Monet', category: 'art', estimatedValue: '$20,000,000-$80,000,000' },
  { name: 'Impression, Sunrise', brand: 'Claude Monet', category: 'art', estimatedValue: 'Priceless' },
  { name: 'Haystacks', brand: 'Claude Monet', category: 'art', estimatedValue: '$110,000,000' },
  // Andy Warhol
  { name: 'Shot Sage Blue Marilyn', brand: 'Andy Warhol', category: 'art', estimatedValue: '$195,000,000' },
  { name: 'Campbell\'s Soup Cans', brand: 'Andy Warhol', category: 'art', estimatedValue: '$50,000,000+' },
  { name: 'Eight Elvises', brand: 'Andy Warhol', category: 'art', estimatedValue: '$100,000,000' },
  { name: 'Triple Elvis', brand: 'Andy Warhol', category: 'art', estimatedValue: '$81,900,000' },
  // Jean-Michel Basquiat
  { name: 'Untitled (Skull)', brand: 'Jean-Michel Basquiat', category: 'art', estimatedValue: '$110,500,000' },
  { name: 'In This Case', brand: 'Jean-Michel Basquiat', category: 'art', estimatedValue: '$93,100,000' },
  { name: 'Warrior', brand: 'Jean-Michel Basquiat', category: 'art', estimatedValue: '$41,900,000' },
  // Banksy
  { name: 'Love is in the Bin', brand: 'Banksy', category: 'art', estimatedValue: '$25,400,000' },
  { name: 'Girl with Balloon', brand: 'Banksy', category: 'art', estimatedValue: '$10,000,000+' },
  { name: 'Devolved Parliament', brand: 'Banksy', category: 'art', estimatedValue: '$12,200,000' },
  // Others
  { name: 'The Scream', brand: 'Edvard Munch', category: 'art', estimatedValue: '$120,000,000' },
  { name: 'The Kiss', brand: 'Gustav Klimt', category: 'art', estimatedValue: 'Priceless' },
  { name: 'Portrait of Adele Bloch-Bauer I', brand: 'Gustav Klimt', category: 'art', estimatedValue: '$135,000,000' },
  { name: 'No. 6 (Violet, Green and Red)', brand: 'Mark Rothko', category: 'art', estimatedValue: '$186,000,000' },
  { name: 'Orange, Red, Yellow', brand: 'Mark Rothko', category: 'art', estimatedValue: '$86,900,000' },
  { name: 'Interchange', brand: 'Willem de Kooning', category: 'art', estimatedValue: '$300,000,000' },
  { name: 'Number 17A', brand: 'Jackson Pollock', category: 'art', estimatedValue: '$200,000,000' },
  { name: 'The Card Players', brand: 'Paul Cézanne', category: 'art', estimatedValue: '$250,000,000' },
  { name: 'Nafea Faa Ipoipo', brand: 'Paul Gauguin', category: 'art', estimatedValue: '$210,000,000' },
  { name: 'Balloon Dog (Orange)', brand: 'Jeff Koons', category: 'art', estimatedValue: '$58,400,000' },
  { name: 'Rabbit', brand: 'Jeff Koons', category: 'art', estimatedValue: '$91,100,000' },
];

// ==================== LUXURY BAGS ($10k+) ====================
const LUXURY_BAGS: ProductModel[] = [
  // Hermès
  { name: 'Birkin 25', brand: 'Hermès', category: 'fashion', estimatedValue: '$10,000-$50,000' },
  { name: 'Birkin 30', brand: 'Hermès', category: 'fashion', estimatedValue: '$12,000-$80,000' },
  { name: 'Birkin 35', brand: 'Hermès', category: 'fashion', estimatedValue: '$10,000-$60,000' },
  { name: 'Birkin Himalaya', brand: 'Hermès', category: 'fashion', estimatedValue: '$200,000-$500,000+' },
  { name: 'Kelly 25', brand: 'Hermès', category: 'fashion', estimatedValue: '$15,000-$40,000' },
  { name: 'Kelly 28', brand: 'Hermès', category: 'fashion', estimatedValue: '$12,000-$35,000' },
  { name: 'Kelly 32', brand: 'Hermès', category: 'fashion', estimatedValue: '$10,000-$30,000' },
  { name: 'Constance', brand: 'Hermès', category: 'fashion', estimatedValue: '$10,000-$30,000' },
  // Chanel
  { name: 'Classic Flap Medium', brand: 'Chanel', category: 'fashion', estimatedValue: '$10,000-$15,000' },
  { name: 'Classic Flap Jumbo', brand: 'Chanel', category: 'fashion', estimatedValue: '$10,000-$18,000' },
  { name: '2.55 Reissue', brand: 'Chanel', category: 'fashion', estimatedValue: '$8,000-$15,000' },
  { name: 'Boy Bag', brand: 'Chanel', category: 'fashion', estimatedValue: '$6,000-$12,000' },
  // Louis Vuitton
  { name: 'Capucines', brand: 'Louis Vuitton', category: 'fashion', estimatedValue: '$5,000-$15,000' },
  { name: 'Petite Malle', brand: 'Louis Vuitton', category: 'fashion', estimatedValue: '$5,000-$15,000' },
];

// ==================== SUPERCARS ($10k+ - actually $100k+) ====================
const SUPERCARS: ProductModel[] = [
  // Ferrari
  { name: '250 GTO', brand: 'Ferrari', category: 'automotive', estimatedValue: '$50,000,000-$70,000,000' },
  { name: '288 GTO', brand: 'Ferrari', category: 'automotive', estimatedValue: '$2,500,000-$4,000,000' },
  { name: 'F40', brand: 'Ferrari', category: 'automotive', estimatedValue: '$1,500,000-$3,000,000' },
  { name: 'F50', brand: 'Ferrari', category: 'automotive', estimatedValue: '$2,000,000-$4,000,000' },
  { name: 'Enzo', brand: 'Ferrari', category: 'automotive', estimatedValue: '$2,500,000-$4,000,000' },
  { name: 'LaFerrari', brand: 'Ferrari', category: 'automotive', estimatedValue: '$3,000,000-$5,000,000' },
  { name: 'SF90 Stradale', brand: 'Ferrari', category: 'automotive', estimatedValue: '$500,000-$800,000' },
  { name: '812 Superfast', brand: 'Ferrari', category: 'automotive', estimatedValue: '$350,000-$500,000' },
  // Lamborghini
  { name: 'Miura', brand: 'Lamborghini', category: 'automotive', estimatedValue: '$1,500,000-$3,000,000' },
  { name: 'Countach', brand: 'Lamborghini', category: 'automotive', estimatedValue: '$500,000-$2,000,000' },
  { name: 'Diablo', brand: 'Lamborghini', category: 'automotive', estimatedValue: '$300,000-$600,000' },
  { name: 'Aventador SVJ', brand: 'Lamborghini', category: 'automotive', estimatedValue: '$500,000-$800,000' },
  { name: 'Revuelto', brand: 'Lamborghini', category: 'automotive', estimatedValue: '$600,000+' },
  // Porsche
  { name: '911 GT3 RS', brand: 'Porsche', category: 'automotive', estimatedValue: '$250,000-$400,000' },
  { name: '918 Spyder', brand: 'Porsche', category: 'automotive', estimatedValue: '$1,500,000-$2,500,000' },
  { name: 'Carrera GT', brand: 'Porsche', category: 'automotive', estimatedValue: '$1,000,000-$2,000,000' },
  // McLaren
  { name: 'F1', brand: 'McLaren', category: 'automotive', estimatedValue: '$15,000,000-$25,000,000' },
  { name: 'P1', brand: 'McLaren', category: 'automotive', estimatedValue: '$1,500,000-$2,500,000' },
  { name: 'Speedtail', brand: 'McLaren', category: 'automotive', estimatedValue: '$2,500,000-$4,000,000' },
  // Bugatti
  { name: 'Veyron', brand: 'Bugatti', category: 'automotive', estimatedValue: '$1,500,000-$3,000,000' },
  { name: 'Chiron', brand: 'Bugatti', category: 'automotive', estimatedValue: '$3,000,000-$4,000,000' },
  { name: 'Chiron Super Sport', brand: 'Bugatti', category: 'automotive', estimatedValue: '$4,000,000+' },
];

// ==================== SPORTS MEMORABILIA ($10k+) ====================
const MEMORABILIA: ProductModel[] = [
  // Michael Jordan
  { name: 'Game-Worn Jersey', brand: 'Michael Jordan', category: 'sports', estimatedValue: '$100,000-$10,000,000+' },
  { name: 'Signed Basketball', brand: 'Michael Jordan', category: 'sports', estimatedValue: '$5,000-$50,000' },
  { name: '1992 Dream Team Jersey', brand: 'Michael Jordan', category: 'sports', estimatedValue: '$50,000-$500,000' },
  // LeBron James
  { name: 'Game-Worn Jersey', brand: 'LeBron James', category: 'sports', estimatedValue: '$50,000-$500,000' },
  { name: 'High School Jersey', brand: 'LeBron James', category: 'sports', estimatedValue: '$100,000+' },
  // Babe Ruth
  { name: 'Game-Worn Jersey', brand: 'Babe Ruth', category: 'sports', estimatedValue: '$5,000,000-$25,000,000' },
  { name: 'Signed Baseball', brand: 'Babe Ruth', category: 'sports', estimatedValue: '$50,000-$500,000' },
  // Muhammad Ali
  { name: 'Fight-Worn Gloves', brand: 'Muhammad Ali', category: 'sports', estimatedValue: '$100,000-$1,000,000' },
  { name: 'Fight-Worn Robe', brand: 'Muhammad Ali', category: 'sports', estimatedValue: '$500,000+' },
  // Tom Brady
  { name: 'Game-Worn Jersey', brand: 'Tom Brady', category: 'sports', estimatedValue: '$50,000-$500,000' },
  { name: 'Super Bowl Jersey', brand: 'Tom Brady', category: 'sports', estimatedValue: '$500,000+' },
];

// Combine all products
export const HIGH_VALUE_PRODUCTS: ProductModel[] = [
  ...ROLEX, ...PATEK, ...AP, ...OTHER_WATCHES,
  ...JORDAN, ...NIKE_SNEAKERS,
  ...POKEMON, ...MTG, ...SPORTS_CARDS,
  ...ARTWORKS,
  ...LUXURY_BAGS,
  ...SUPERCARS,
  ...MEMORABILIA,
];

/**
 * Search products by brand name
 */
export function searchProductsByBrand(brandName: string, query: string = '', limit: number = 20): ProductModel[] {
  const brandLower = brandName.toLowerCase();
  const queryLower = query.toLowerCase().trim();

  // Find products matching the brand
  let matches = HIGH_VALUE_PRODUCTS.filter(p => {
    const productBrand = p.brand.toLowerCase();
    return productBrand === brandLower || 
           productBrand.includes(brandLower) || 
           brandLower.includes(productBrand);
  });

  // If query provided, filter by product name
  if (queryLower.length > 0) {
    matches = matches.filter(p => {
      const nameLower = p.name.toLowerCase();
      if (nameLower.includes(queryLower)) return true;
      if (p.aliases) {
        return p.aliases.some(a => a.toLowerCase().includes(queryLower));
      }
      return false;
    });
  }

  // Sort by name
  matches.sort((a, b) => a.name.localeCompare(b.name));

  return matches.slice(0, limit);
}

/**
 * Get all unique brands that have products in the database
 */
export function getBrandsWithProducts(): string[] {
  const brands = new Set<string>();
  for (const p of HIGH_VALUE_PRODUCTS) {
    brands.add(p.brand);
  }
  return Array.from(brands).sort();
}
